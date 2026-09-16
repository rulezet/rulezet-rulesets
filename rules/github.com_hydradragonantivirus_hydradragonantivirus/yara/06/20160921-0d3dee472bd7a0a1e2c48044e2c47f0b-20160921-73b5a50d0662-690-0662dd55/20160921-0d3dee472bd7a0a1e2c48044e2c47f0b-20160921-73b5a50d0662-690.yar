rule _20160921_0d3dee472bd7a0a1e2c48044e2c47f0b_20160921_73b5a50d0662_690 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d3dee472bd7a0a1e2c48044e2c47f0b.js, 20160921_73b5a50d06622b8411077815f2717627.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ffda0cd0cd96558031ec49484507d0af3efe8f0ec6fee33e947b4b9515ab24f"
    hash2       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"

  strings:
    $s1  = "n \"IPu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s2  = "{return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})" ascii
    $s3  = "urn \"SEo\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TRc\";})()," ascii
    $s4  = "f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot" ascii
    $s5  = "{return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(" ascii
    $s6  = " f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Q" ascii
    $s7  = "})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f0" ascii
    $s8  = "f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\"" ascii
    $s9  = "n \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s10 = ")(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"OUx\";})(),(function f000" ascii
    $s11 = "000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZG" ascii
    $s12 = "nction f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){retu" ascii
    $s13 = "0(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq" ascii
    $s14 = "\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s15 = " f000(){return \"Qj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"V" ascii
    $s16 = "ion f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s17 = "turn \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(" ascii
    $s18 = "on f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii
    $s19 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"SGs\";})(" ascii
    $s20 = "urn \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}