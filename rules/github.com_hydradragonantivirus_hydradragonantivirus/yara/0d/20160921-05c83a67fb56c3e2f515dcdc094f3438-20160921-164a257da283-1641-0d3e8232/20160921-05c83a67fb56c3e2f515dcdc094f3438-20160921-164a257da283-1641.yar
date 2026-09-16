rule _20160921_05c83a67fb56c3e2f515dcdc094f3438_20160921_164a257da283_1641 {
  meta:
    description = "datamaliciousorder - from files 20160921_05c83a67fb56c3e2f515dcdc094f3438.js, 20160921_164a257da283d5c859dcaffb21bf752c.js, 20160921_56567a449e5ae44cd4a4e62bb55e63f3.js, 20160921_a0b892850e7511a70b7c95d4603de0d8.js, 20160921_fb2ccc1a635114bc23ea8a0a8413b110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0535a055f646391a67e495ab3466f375b47d00382cf1ac28c70355309533f19c"
    hash2       = "36edb416a5f8703ead3fb8f8fbb7a0fb98ac21c559eb20558b33460ba9dfc9a0"
    hash3       = "e0950a0ccf96b116ed17c3fbaa99325e34f0b717e3e354bd1f926eee8465c6a7"
    hash4       = "0b5459eb728a278a131a764184d1d333fcd3fc212087b66d9cedce792b1a2d7a"
    hash5       = "c85e7d8e5c1682f21f2d8c9a0e1f6039d583d7eda8276ca9ed3ed381fbde9a7e"

  strings:
    $s1  = "{return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(" ascii
    $s2  = "\"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"DAa\";})(),(func" ascii
    $s3  = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ug\";})(),(function fuck" ascii
    $s4  = "function fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){re" ascii
    $s5  = "k(){return \"OQr\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"DRx" ascii
    $s6  = "(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";" ascii
    $s7  = "n fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii
    $s8  = "t\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function" ascii
    $s9  = "IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IRn\";})(),(funct" ascii
    $s10 = "function fuck(){return \"Jo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){re" ascii
    $s11 = "MIl\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}