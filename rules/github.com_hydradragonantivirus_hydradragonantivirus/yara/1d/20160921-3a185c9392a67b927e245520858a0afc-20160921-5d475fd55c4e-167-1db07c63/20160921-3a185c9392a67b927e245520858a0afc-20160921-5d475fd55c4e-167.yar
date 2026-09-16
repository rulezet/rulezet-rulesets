rule _20160921_3a185c9392a67b927e245520858a0afc_20160921_5d475fd55c4e_167 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a185c9392a67b927e245520858a0afc.js, 20160921_5d475fd55c4e461509ccd87876cf56f7.js, 20160921_d4a195112732d8d5ebb1bdc900a52d50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5201f237db515e70a3934feb4ff64c4cccf728f340d6e9e46fbe4217f988165"
    hash2       = "dc4e4001f0f2e1f28098f6ad190b918a7ffe075d590fb142a508fdad546d9816"
    hash3       = "679537ccc73765d47769657cc000499c86fa227678df5b0d4690ca0e2cf6325c"

  strings:
    $s1  = "000(){return \"EZu\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s2  = "000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn" ascii
    $s3  = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"" ascii
    $s4  = ",(function f000(){return \"Go\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s5  = "\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Kw\";})(),(function f" ascii
    $s6  = "f000(){return \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br" ascii
    $s7  = "Gn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NYh\";})(),(function" ascii
    $s8  = "ction f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DYx\";})(),(function f000(){retu" ascii
    $s9  = "f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Iq" ascii
    $s10 = "f000(){return \"Um\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn" ascii
    $s11 = "turn \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s12 = "f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"MJ" ascii
    $s13 = "unction f000(){return \"ZFe\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){ret" ascii
    $s14 = "return \"KXg\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Br\";})()" ascii
    $s15 = "turn \"Wb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s16 = "00(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"YTp" ascii
    $s17 = "turn \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(" ascii
    $s18 = "\"QDg\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qz\";})(),(funct" ascii
    $s19 = "rn \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oh\";})(),(f" ascii
    $s20 = "GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Oh\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}