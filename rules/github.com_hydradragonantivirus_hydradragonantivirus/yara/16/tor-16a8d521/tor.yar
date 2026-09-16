rule Tor {
  meta:
    description   = "Detection patterns for the tool 'Tor' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "Tor"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /\/proxy\/Tor\.py/ nocase ascii wide
            $string2 = /\/proxy\/tor_paths\.py/ nocase ascii wide
            $string3 = /\/tor\-gencert\.exe/ nocase ascii wide
            $string4 = /\/win\/Tor\/tor\.exe/ nocase ascii wide
            $string5 = /r0oth3x49\/Tor\.git/ nocase ascii wide
            $string6 = /tor_services\.py/ nocase ascii wide
            $string7 = /TorServiceSetup/ nocase ascii wide

  condition:
    any of them
}