rule _20160517_22adad398119ee9e1921392208b569e0_20160517_37ea41a279fa_1069 {
  meta:
    description = "datamaliciousorder - from files 20160517_22adad398119ee9e1921392208b569e0.js, 20160517_37ea41a279faba99bab68e0e23c0ee0b.js, 20160517_ea70cd72774290810435e33fa04d587d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f0dae542d87569dc4e470a31f7f04eacc0fe1e732f63d91c44fc0795ef16fcf"
    hash2       = "873b2ff197404b7afa6ee518a86de415c74b3aed6e860c3257b3af5f066c4be1"
    hash3       = "aaa49914a6576c11f737787b0b889ae8cc02521738b50d8d8817deaa2cdce01c"

  strings:
    $s1 = "var nConverts1 /* E  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* E  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* E  */;};" fullword ascii
    $s4 = "var enjoy1 /* E  */ = false;" fullword ascii
    $s5 = "could = /* E  */(/* E  */\"noitisop\").split(''/* E  */).reverse(/* E  */).join('');" fullword ascii
    $s6 = "enjoy1 /* E  */ /* E  */= true;/* E  */" fullword ascii
    $s7 = "batch =/* E  */ \"R\" + \"esponseB\"/* E  */ + \"ydo\".split('').reverse().join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}