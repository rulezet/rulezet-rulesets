rule _20160921_22511056ddb6d59ffb3e56c3b7382182_20160921_f926399cbb63_1682 {
  meta:
    description = "datamaliciousorder - from files 20160921_22511056ddb6d59ffb3e56c3b7382182.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"
    hash2       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1  = "(function fuck(){return \"GWo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s2  = " fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"" ascii
    $s3  = "),(function fuck(){return \"GWo\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(" ascii
    $s4  = "ion fuck(){return \"Xg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5  = "on fuck(){return \"XHj\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s6  = "urn \"Jh\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s7  = "rn \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Av\";})(),(f" ascii
    $s8  = "nction fuck(){return \"CCb\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii
    $s9  = "ck(){return \"QTc\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\"" ascii
    $s10 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"EHo\";})(),(function fuc" ascii
    $s11 = "z\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ar\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}