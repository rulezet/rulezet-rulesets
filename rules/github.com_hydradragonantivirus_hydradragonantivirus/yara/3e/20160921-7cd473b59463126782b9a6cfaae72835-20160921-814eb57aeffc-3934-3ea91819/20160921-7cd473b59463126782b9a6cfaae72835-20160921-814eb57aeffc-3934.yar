rule _20160921_7cd473b59463126782b9a6cfaae72835_20160921_814eb57aeffc_3934 {
  meta:
    description = "datamaliciousorder - from files 20160921_7cd473b59463126782b9a6cfaae72835.js, 20160921_814eb57aeffc75442964829345cc9f96.js, 20160921_89a260f4d6da4d97f251f843cf5e94b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"
    hash2       = "2736df4d651a33824aba7abffa7c08414414ffed9f5f27b4b2d81101cfeb7117"
    hash3       = "700f6c802eb024896efe2b22255973b53752a8f129213c9bba2c4f2ebdc53988"

  strings:
    $s1 = "urn \"Oe\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(fu" ascii
    $s2 = "tion f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s3 = "return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})()" ascii
    $s4 = "return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(" ascii
    $s5 = "(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";" ascii
    $s6 = "g\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}