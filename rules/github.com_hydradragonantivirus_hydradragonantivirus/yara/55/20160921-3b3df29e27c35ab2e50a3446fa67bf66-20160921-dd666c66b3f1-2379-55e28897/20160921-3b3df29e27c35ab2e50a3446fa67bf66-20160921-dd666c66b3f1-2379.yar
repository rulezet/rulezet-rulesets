rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_dd666c66b3f1_2379 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = "00(){return \"KXg\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s2 = "j\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function " ascii
    $s3 = "urn \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s4 = "(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s5 = ")(),(function f000(){return \"Vu\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s6 = "\"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s7 = "Pt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s8 = "(){return \"Yz\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}