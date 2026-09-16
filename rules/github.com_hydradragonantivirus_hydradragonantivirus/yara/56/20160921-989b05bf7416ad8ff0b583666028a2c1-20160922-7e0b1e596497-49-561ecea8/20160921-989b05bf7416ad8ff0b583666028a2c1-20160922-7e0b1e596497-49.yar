rule _20160921_989b05bf7416ad8ff0b583666028a2c1_20160922_7e0b1e596497_49 {
  meta:
    description = "datamaliciousorder - from files 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash2       = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"

  strings:
    $s1  = "function f000(){return \"Qj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){ret" ascii
    $s2  = " f000(){return \"KDh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"D" ascii
    $s3  = "000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut" ascii
    $s4  = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){ret" ascii
    $s5  = "000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz" ascii
    $s6  = "\"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(functi" ascii
    $s7  = "eturn \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(f" ascii
    $s8  = "000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg" ascii
    $s9  = ";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s10 = "f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RP" ascii
    $s11 = "return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})()," ascii
    $s12 = "SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(functi" ascii
    $s13 = "n\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function" ascii
    $s14 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"RLk\"" ascii
    $s15 = "n \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s16 = "nction f000(){return \"WIj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s17 = "Md\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(functio" ascii
    $s18 = "tion f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s19 = "tion f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DNa\";})(),(function f000(){retur" ascii
    $s20 = "Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}