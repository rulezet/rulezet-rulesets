rule wce0 {
  meta:
    description   = "Detection patterns for the tool 'wce' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "wce"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1  = /\/returnvar\/wce\// nocase ascii wide
            $string2  = /\/share\/windows\-resources\/wce/ nocase ascii wide
            $string3  = /\/wce32\.exe/ nocase ascii wide
            $string4  = /\/wce64\.exe/ nocase ascii wide
            $string5  = /\/wce\-beta\.zip/ nocase ascii wide
            $string6  = /\\wce32\.exe/ nocase ascii wide
            $string7  = /\\wce64\.exe/ nocase ascii wide
            $string8  = /\\wce\-beta\.zip/ nocase ascii wide
            $string9  = /apt\sinstall\swce/ nocase ascii wide
            $string10 = /wce\s\-i\s3e5\s\-s\s/ nocase ascii wide
            $string11 = /wce.*getlsasrvaddr\.exe/ nocase ascii wide
            $string12 = /wce\-master\.zip/ nocase ascii wide
            $string13 = /wce\-universal\.exe/ nocase ascii wide

  condition:
    any of them
}