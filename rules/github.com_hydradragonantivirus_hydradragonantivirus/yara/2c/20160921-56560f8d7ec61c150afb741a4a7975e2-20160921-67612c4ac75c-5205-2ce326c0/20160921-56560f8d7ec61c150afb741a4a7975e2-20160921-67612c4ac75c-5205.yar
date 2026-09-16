rule _20160921_56560f8d7ec61c150afb741a4a7975e2_20160921_67612c4ac75c_5205 {
  meta:
    description = "datamaliciousorder - from files 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_67612c4ac75c1d3511dd9358b66e9fc5.js, 20160921_8881f4de1f94ec992ad3832b292063a8.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash2       = "fbf6986e3a8c7defa5c14d80cff4f3b3ce1db859ea94044f5d024758684178c0"
    hash3       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"
    hash4       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"
    hash5       = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1 = "ck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";" ascii
    $s2 = "\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function f" ascii
    $s3 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck()" ascii
    $s4 = "n fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s5 = "eturn \"Ik\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MUs\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}