rule _0d1n {
  meta:
    description   = "Detection patterns for the tool '0d1n' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "0d1n"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1  = /\/0d1n\.c/ nocase ascii wide
            $string2  = /\/0d1n_view/ nocase ascii wide
            $string3  = /\/bin\/0d1n/ nocase ascii wide
            $string4  = /\/crlfinjection\.txt/ nocase ascii wide
            $string5  = /\/dir_brute\.txt/ nocase ascii wide
            $string6  = /\/js_inject\.txt/ nocase ascii wide
            $string7  = /\/ldap_injection\.txt/ nocase ascii wide
            $string8  = /\/passive_sqli\.txt/ nocase ascii wide
            $string9  = /\/password_brute\.txt/ nocase ascii wide
            $string10 = /\/path_traversal\.txt/ nocase ascii wide
            $string11 = /\/path_traversal_win32\.txt/ nocase ascii wide
            $string12 = /\/sqli\.txt/ nocase ascii wide
            $string13 = /\/xml_attack\.txt/ nocase ascii wide
            $string14 = /\/xml_attacks\.txt/ nocase ascii wide
            $string15 = /\/xpath_injection\.txt/ nocase ascii wide
            $string16 = /\/xss_robertux\.txt/ nocase ascii wide
            $string17 = /\/xxe_fuzz\.txt/ nocase ascii wide
            $string18 = /0d1n\s.*\s\-\-post\s.*\s\-\-payloads\s/ nocase ascii wide
            $string19 = /0d1n\s\-\-host/ nocase ascii wide
            $string20 = /0d1n.*kill_listener\.sh/ nocase ascii wide
            $string21 = /CoolerVoid\/0d1n/ nocase ascii wide

  condition:
    any of them
}