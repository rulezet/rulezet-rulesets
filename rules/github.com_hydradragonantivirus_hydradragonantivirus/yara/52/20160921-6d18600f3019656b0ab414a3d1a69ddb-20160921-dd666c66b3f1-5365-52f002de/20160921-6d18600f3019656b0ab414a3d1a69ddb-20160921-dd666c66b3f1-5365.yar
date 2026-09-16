rule _20160921_6d18600f3019656b0ab414a3d1a69ddb_20160921_dd666c66b3f1_5365 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = ")(),(function f000(){return \"Wb\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Wb\";})(),(function f000()" ascii
    $s2 = "nction f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){retu" ascii
    $s3 = "ion f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"UEg\";})(),(function f000(){return" ascii
    $s4 = "return \"IPu\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s5 = "n \"Wb\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Wb\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}