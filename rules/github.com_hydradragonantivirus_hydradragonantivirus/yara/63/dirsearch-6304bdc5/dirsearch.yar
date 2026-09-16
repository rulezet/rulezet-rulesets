rule dirsearch {
  meta:
    description   = "Detection patterns for the tool 'dirsearch' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "dirsearch"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /dirsearch/ nocase ascii wide

  condition:
    any of them
}