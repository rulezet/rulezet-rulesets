rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_1766f5c818d6_1639 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_1766f5c818d6371cb36488c98158ccd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"

  strings:
    $s1  = "urn \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s2  = "ion f000(){return \"Br\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"" ascii
    $s3  = ";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s4  = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"BMj" ascii
    $s5  = ";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"TKp\";})(),(function f" ascii
    $s6  = " f000(){return \"Wy\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii
    $s7  = "nction f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MJq\";})(),(function f000(){retu" ascii
    $s8  = "(){return \"Wh\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Lo\";})" ascii
    $s9  = "\"Br\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(functi" ascii
    $s10 = "{return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})()" ascii
    $s11 = "turn \"SEo\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}