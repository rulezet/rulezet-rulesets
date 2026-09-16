rule onionscan {
  meta:
    description   = "Detection patterns for the tool 'onionscan' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "onionscan"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /OnionScan/ nocase ascii wide

  condition:
    any of them
}