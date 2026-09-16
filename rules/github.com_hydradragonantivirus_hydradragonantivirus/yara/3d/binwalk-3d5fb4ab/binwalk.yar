rule binwalk {
  meta:
    description   = "Detection patterns for the tool 'binwalk' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "binwalk"
    rule_category = "greyware_tool_keyword"

  strings:
            $string1 = /binwalk/ nocase ascii wide

  condition:
    any of them
}