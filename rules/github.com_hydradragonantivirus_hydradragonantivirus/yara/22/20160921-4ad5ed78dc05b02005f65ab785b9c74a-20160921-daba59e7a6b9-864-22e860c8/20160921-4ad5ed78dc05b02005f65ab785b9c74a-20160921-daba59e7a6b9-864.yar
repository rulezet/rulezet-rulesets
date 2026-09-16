rule _20160921_4ad5ed78dc05b02005f65ab785b9c74a_20160921_daba59e7a6b9_864 {
  meta:
    description = "datamaliciousorder - from files 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1  = "on f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return " ascii
    $s2  = "),(function f000(){return \"MMz\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"MDb\";})(),(function f000()" ascii
    $s3  = "eturn \"Rh\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s4  = "urn \"Br\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Br\";})(),(fu" ascii
    $s5  = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"ZFe\";})(),(" ascii
    $s6  = "turn \"KDh\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(" ascii
    $s7  = "(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MDb\"" ascii
    $s8  = " f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj" ascii
    $s9  = "ion f000(){return \"Sv\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s10 = "000(){return \"Br\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br" ascii
    $s11 = "unction f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s12 = "000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Sq" ascii
    $s13 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"IAa\";})(),(function f" ascii
    $s14 = "){return \"Oe\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Vj\";})(" ascii
    $s15 = "nction f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii
    $s16 = "n \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Tn\";})(),(func" ascii
    $s17 = "(),(function f000(){return \"YTp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000()" ascii
    $s18 = ";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f00" ascii
    $s19 = " f000(){return \"MMz\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"P" ascii
    $s20 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"MMz\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}