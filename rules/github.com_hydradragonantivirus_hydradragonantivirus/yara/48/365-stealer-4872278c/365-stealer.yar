rule _365_Stealer {
  meta:
    description   = "Detection patterns for the tool '365-Stealer' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "365-Stealer"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1  = /\s365\-Stealer\s/ nocase ascii wide
            $string2  = /\s\-\-custom\-steal/ nocase ascii wide
            $string3  = /\s\-\-custom\-steal\slistusers/ nocase ascii wide
            $string4  = /\s\-\-custom\-steal\sonedrive/ nocase ascii wide
            $string5  = /\s\-\-custom\-steal\sonenote/ nocase ascii wide
            $string6  = /\s\-\-custom\-steal\soutlook/ nocase ascii wide
            $string7  = /\sRedirect\sUrl\sAfter\sStealing\s\=\=\>\s/ nocase ascii wide
            $string8  = /\/365\-Stealer\.git/ nocase ascii wide
            $string9  = /\[\!\]\sLooks\slike\sVictim\s.*\sdoesn\'t\shave\soffice365\sLicence\!/ nocase ascii wide
            $string10 = /\[\!\]\sStealing\sprocesses\sdelayed\swith\s/ nocase ascii wide
            $string11 = /\[\!\]\sSwithed\sto\scustom\sstealing\.\s/ nocase ascii wide
            $string12 = /\[\+\]\sVictim\s.*\shave\soffice365\sLicence\!/ nocase ascii wide
            $string13 = /365\-Stealer\.py/ nocase ascii wide
            $string14 = /365\-Stealer\-master/ nocase ascii wide
            $string15 = /AlteredSecurity\/365\-Stealer/ nocase ascii wide
            $string16 = /cscript\s\.\.\\\\temp\.vbs/ nocase ascii wide
            $string17 = /\'Disable\sall\shttp\saccess\slogs\'/ nocase ascii wide
            $string18 = /\'Host\sthe\sPhising\sApp\'/ nocase ascii wide
            $string19 = /MIIEowIBAAKCAQEAvZtOCbMyFKJN3n89nctTfYLSeiCTNG01rAFl06hMkobyzr0c/ nocase ascii wide
            $string20 = /o365\-Attack\-Toolkit/ nocase ascii wide

  condition:
    any of them
}