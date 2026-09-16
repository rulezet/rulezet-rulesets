rule _20160921_3d472332b6f7d53a9f60478e1312ea58_20160921_90c3374aed1b_3689 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_90c3374aed1b4618a92eb40cb007c4b4.js, 20160921_e1835bc92c4604db194bc49df621cade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash2       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"
    hash3       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"

  strings:
    $s1 = "ion f000(){return \"Tn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return " ascii
    $s2 = "urn \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})()," ascii
    $s3 = "n f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Y" ascii
    $s4 = "{return \"Vj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(" ascii
    $s5 = "),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){" ascii
    $s6 = "Ia\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}