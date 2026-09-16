rule MC_Office_DDE_Command_Execution {
  meta:
    Author      = "InQuest Labs"
    URL         = "https://github.com/InQuest/yara-rules"
    Description = "This rule looks for a variety of DDE command execution techniques."

  strings:
    

        $dde = />\s*DDE(AUTO)?\s*</ nocase wide ascii

            $dde_auto = /<\s*w:fldChar\s+w:fldCharType\s*=\s*['"]begin['"]\s*\/>.+[^A-Za-z0-9-]DDEAUTO[^A-Za-z0-9-].+<w:fldChar\s+w:fldCharType\s*=\s*['"]end['"]\s*\/>/ nocase wide ascii

        $dde_other = /<\s*w:fldChar\s+w:fldCharType\s*=\s*['"]begin['"]\s*\/>.+[^A-Za-z0-9-]DDE[B-Zb-z]+[^A-Za-z0-9-].+<w:fldChar\s+w:fldCharType\s*=\s*['"]end['"]\s*\/>/ nocase wide ascii

        $magic         = /^\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00/
    $wide_dde_auto = /.+[^A-Za-z0-9-]DDEAUTO[^a-z0-9-].+/ nocase wide ascii

                        $early_exit       = "fldChar" nocase wide ascii
            $xml_obfuscated_2 = />\s*["']?DD\s*</ nocase ascii wide
    $xml_obfuscated_3 = />\s*["']?DDE\s*</ nocase ascii wide
            
        $pure_xml_dde = /<\s*ddeLink[^>]+ddeService\s*=\s*["'](cmd|reg|mshta|regsvr32|[wc]script|powershell|bitsadmin|schtasks|rundll32)["'][^>]+ddeTopic/ nocase wide ascii

        $exec_action = /(cmd\.exe|reg\.exe|mshta\.exe|regsvr32|[wc]script|powershell|bitsadmin|schtasks|rundll32)/ nocase wide ascii

        $quote_obfuscation = /w:instr\s*=\s*["']\s*QUOTE\s+\d+\s+/ nocase wide ascii

  condition:
    ((any of ($dde*) or ($magic at 0 and $wide_dde_auto)) and ($exec_action or $quote_obfuscation))
    or
    ($early_exit and any of ($xml_obfuscated*))
    or
    ($pure_xml_dde)
    or
    (
                        for any i in (0..30): ((uint32be(i) | 0x2020) == 0x7b5c7274 and $exec_action)
    )
}