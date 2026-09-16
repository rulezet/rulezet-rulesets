rule Cobaltstrike {
  meta:
    description   = "Detection patterns for the tool 'Cobaltstrike' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "Cobaltstrike"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1  = /\/PoolPartyBof\.c/ nocase ascii wide
            $string2  = /\/PoolPartyBof\.git/ nocase ascii wide
            $string3  = /\/PoolPartyBof\.x64\.o/ nocase ascii wide
            $string4  = /0xEr3bus\/PoolPartyBof/ nocase ascii wide
            $string5  = /Allocated\sshellcode\smemory\sin\sthe\starget\sprocess\:\s/ nocase ascii wide
            $string6  = /PoolParty\sattack\scompleted\ssuccessfully/ nocase ascii wide
            $string7  = /PoolPartyBof\s/ nocase ascii wide
            $string8  = /PoolPartyBof\s.{0,1000}\sHTTPSLocal/ nocase ascii wide
            $string9  = /PoolPartyBof\.cna/ nocase ascii wide
            $string10 = /PoolPartyBof\-main/ nocase ascii wide
            $string11 = /Starting\sPoolParty\sattack\sagainst\sprocess\sid\:/ nocase ascii wide

  condition:
    any of them
}