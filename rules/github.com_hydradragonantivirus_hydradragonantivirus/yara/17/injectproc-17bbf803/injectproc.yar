rule InjectProc {
  meta:
    description   = "Detection patterns for the tool 'InjectProc' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "InjectProc"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /InjectProc/ nocase ascii wide

  condition:
    any of them
}