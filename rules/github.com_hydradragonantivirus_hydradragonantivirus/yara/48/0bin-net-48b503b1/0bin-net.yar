rule _0bin_net {
  meta:
    description   = "Detection patterns for the tool '0bin.net' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "0bin.net"
    rule_category = "greyware_tool_keyword"

  strings:
            $string1 = /0bin\s\-\sencrypted\spastebin/ nocase ascii wide
            $string2 = /A\sclient\sside\sencrypted\sPasteBin/ nocase ascii wide
            $string3 = /https\:\/\/0bin\.net\/paste\/.{0,1000}\+/ nocase ascii wide
            $string4 = /https\:\/\/0bin\.net\/paste\/create/ nocase ascii wide

  condition:
    any of them
}