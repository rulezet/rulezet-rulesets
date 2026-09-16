rule bloodhound {
  meta:
    description   = "Detection patterns for the tool 'bloodhound' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "bloodhound"
    rule_category = "greyware_tool_keyword"

  strings:
            $string1 = /neo4j\sconsole/ nocase ascii wide

  condition:
    any of them
}