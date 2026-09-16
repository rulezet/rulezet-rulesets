rule SlowLoris {
  meta:
    description   = "Detection patterns for the tool 'SlowLoris' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "SlowLoris"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /SlowLoris/ nocase ascii wide

  condition:
    any of them
}