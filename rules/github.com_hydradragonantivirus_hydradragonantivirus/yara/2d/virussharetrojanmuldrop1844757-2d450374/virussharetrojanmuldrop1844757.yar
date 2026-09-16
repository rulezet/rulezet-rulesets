rule VirusShareTrojanMulDrop1844757 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanMulDrop1844757.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c839c357b85bc65e982067f854d9ba66914b2177f3301e61320ae9c521278c6"

  strings:
    $s1 = "START CMD /C \"ECHO File corrupted! This application has been manipulated. && PAUSE\" " fullword wide
    $s2 = ".Beds Protector v1.4.1 | Public Version @Github" fullword ascii
    $s3 = "op:0px;left:0px\"><IMG/src=\"#\"onerror=\"window.open(&quot;http://goo.gl/YroZm&quot;,&quot;&quot;,&quot;fullscreen=yes&quot;)\"" ascii
    $s4 = "\"onclick=\"return(false);\"style=\"background:#ffffff;cursor:default;position:absolute;display:block;width:10000px;height:10000" ascii
    $s5 = "#<MODULE>" fullword ascii
    $s6 = "\"onclick=\"return(false);\"style=\"background:#ffffff;cursor:default;position:absolute;display:block;width:10000px;height:10000" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}