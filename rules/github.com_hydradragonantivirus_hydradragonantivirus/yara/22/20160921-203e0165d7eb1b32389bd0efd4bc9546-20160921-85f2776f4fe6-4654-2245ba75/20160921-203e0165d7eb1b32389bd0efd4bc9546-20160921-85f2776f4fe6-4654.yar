rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_85f2776f4fe6_4654 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_85f2776f4fe640d2373f51ddbc697659.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "0604503e68d6aa73ca3bbdb29b958ea47ad4c81b2f77ad9db2b0e8467b1c870d"
    hash3       = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"

  strings:
    $s1 = "(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s2 = ")(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck()" ascii
    $s3 = "n \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s4 = "tion fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return " ascii
    $s5 = "(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}