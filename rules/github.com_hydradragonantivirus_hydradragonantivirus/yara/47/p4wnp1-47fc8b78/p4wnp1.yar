rule P4wnP1 {
  meta:
    description   = "Detection patterns for the tool 'P4wnP1' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "P4wnP1"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /P4wnP1/ nocase ascii wide

  condition:
    any of them
}