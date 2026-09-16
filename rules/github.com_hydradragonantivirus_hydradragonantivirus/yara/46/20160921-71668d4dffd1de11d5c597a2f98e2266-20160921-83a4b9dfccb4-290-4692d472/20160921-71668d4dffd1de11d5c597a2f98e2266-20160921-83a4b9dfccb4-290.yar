rule _20160921_71668d4dffd1de11d5c597a2f98e2266_20160921_83a4b9dfccb4_290 {
  meta:
    description = "datamaliciousorder - from files 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_99d82d33214407e421e255b85f02daae.js, 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js, 20160921_dc989bc33de845eef9826b241e933829.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash2       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash3       = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"
    hash4       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"
    hash5       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"

  strings:
    $s1  = "})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000" ascii
    $s2  = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){retur" ascii
    $s3  = "n f000(){return \"Uo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"S" ascii
    $s4  = "n \"MJq\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s5  = "\"MJq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s6  = " f000(){return \"Br\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"HJ" ascii
    $s7  = "),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"MBb\";})(),(function f000(" ascii
    $s8  = " f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"X" ascii
    $s9  = "ction f000(){return \"HJm\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"RVb\";})(),(function f000(){retu" ascii
    $s10 = " f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YT" ascii
    $s11 = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oh" ascii
    $s12 = "unction f000(){return \"Sj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){retu" ascii
    $s13 = "})(),(function f000(){return \"Br\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nv\";})(),(function f000" ascii
    $s14 = "n f000(){return \"Mc\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GG" ascii
    $s15 = "turn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"YTp\";})(),(" ascii
    $s16 = "\"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"NBs\";})(),(functi" ascii
    $s17 = "\"Iq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"UEg\";})(),(funct" ascii
    $s18 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"EZu\";})(),(function f000(){return " ascii
    $s19 = "000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"ZFe" ascii
    $s20 = " \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Sq\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}