rule _20160921_0e1bfa63bcb2804e89834c330285643e_20160921_ad1fccc6910b_3337 {
  meta:
    description = "datamaliciousorder - from files 20160921_0e1bfa63bcb2804e89834c330285643e.js, 20160921_ad1fccc6910bd9c4a47aa9bd3e9239da.js, 20160921_afb633ee817d9b15b91ed82a059939fc.js, 20160921_e39622eeb1da8fbbf03ca86989251a47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d58b57cb825244d35e22402fcf08c9ababcc51eb72a7913c47dbb2143171df32"
    hash2       = "a49fc1cb85eaa58b7c63197e9fd25224f63dcb6c86b906933f698898634ead3e"
    hash3       = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"
    hash4       = "e0b1660f1c95284f1a0f8062a1f16e26aa3d58e3fa4cf47fc04824d02b754a56"

  strings:
    $s1 = "unction fuck(){return \"DAa\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){re" ascii
    $s2 = "Hd\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xw\";})(),(function" ascii
    $s3 = "turn \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(" ascii
    $s4 = "(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\"" ascii
    $s5 = ")(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuc" ascii
    $s6 = "OQr\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Za\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}