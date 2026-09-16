rule _20160921_05c83a67fb56c3e2f515dcdc094f3438_20160921_0e1bfa63bcb2_4239 {
  meta:
    description = "datamaliciousorder - from files 20160921_05c83a67fb56c3e2f515dcdc094f3438.js, 20160921_0e1bfa63bcb2804e89834c330285643e.js, 20160921_ad1fccc6910bd9c4a47aa9bd3e9239da.js, 20160921_e39622eeb1da8fbbf03ca86989251a47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0535a055f646391a67e495ab3466f375b47d00382cf1ac28c70355309533f19c"
    hash2       = "d58b57cb825244d35e22402fcf08c9ababcc51eb72a7913c47dbb2143171df32"
    hash3       = "a49fc1cb85eaa58b7c63197e9fd25224f63dcb6c86b906933f698898634ead3e"
    hash4       = "e0b1660f1c95284f1a0f8062a1f16e26aa3d58e3fa4cf47fc04824d02b754a56"

  strings:
    $s1 = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s2 = "turn \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(" ascii
    $s3 = "){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";" ascii
    $s4 = "ck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\"" ascii
    $s5 = "unction fuck(){return \"ZWu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}