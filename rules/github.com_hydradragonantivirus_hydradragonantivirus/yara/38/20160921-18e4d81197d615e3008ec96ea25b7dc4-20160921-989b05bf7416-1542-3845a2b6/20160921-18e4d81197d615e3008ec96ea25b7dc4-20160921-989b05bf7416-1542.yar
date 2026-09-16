rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_989b05bf7416_1542 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash3       = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"

  strings:
    $s1  = "{return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(" ascii
    $s2  = "n \"OUx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(fu" ascii
    $s3  = "(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";}" ascii
    $s4  = "(),(function f000(){return \"ZFe\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000" ascii
    $s5  = "Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function" ascii
    $s6  = " \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Wh\";})(),(func" ascii
    $s7  = "0(){return \"NBs\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s8  = ")(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000()" ascii
    $s9  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s10 = "urn \"RLk\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Kw\";})(),(fu" ascii
    $s11 = "turn \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s12 = "(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}