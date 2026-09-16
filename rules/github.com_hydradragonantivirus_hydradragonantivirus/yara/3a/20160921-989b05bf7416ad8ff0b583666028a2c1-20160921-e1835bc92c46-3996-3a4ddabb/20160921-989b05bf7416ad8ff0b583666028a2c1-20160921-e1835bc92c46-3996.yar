rule _20160921_989b05bf7416ad8ff0b583666028a2c1_20160921_e1835bc92c46_3996 {
  meta:
    description = "datamaliciousorder - from files 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160921_e1835bc92c4604db194bc49df621cade.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash2       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"
    hash3       = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"

  strings:
    $s1 = "function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){re" ascii
    $s2 = "Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Vj\";})(),(functio" ascii
    $s3 = "f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy" ascii
    $s4 = "),(function f000(){return \"Ot\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){" ascii
    $s5 = "eturn \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})()," ascii
    $s6 = "n f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"G" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}