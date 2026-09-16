rule weevely {
  meta:
    description   = "Detection patterns for the tool 'weevely' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "weevely"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /\/Weevely/ nocase ascii wide

  condition:
    any of them
}