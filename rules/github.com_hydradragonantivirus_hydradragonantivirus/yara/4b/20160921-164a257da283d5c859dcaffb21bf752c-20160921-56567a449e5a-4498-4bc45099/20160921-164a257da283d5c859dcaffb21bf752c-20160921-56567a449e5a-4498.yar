rule _20160921_164a257da283d5c859dcaffb21bf752c_20160921_56567a449e5a_4498 {
  meta:
    description = "datamaliciousorder - from files 20160921_164a257da283d5c859dcaffb21bf752c.js, 20160921_56567a449e5ae44cd4a4e62bb55e63f3.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js, 20160921_a0b892850e7511a70b7c95d4603de0d8.js, 20160921_fb2ccc1a635114bc23ea8a0a8413b110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36edb416a5f8703ead3fb8f8fbb7a0fb98ac21c559eb20558b33460ba9dfc9a0"
    hash2       = "e0950a0ccf96b116ed17c3fbaa99325e34f0b717e3e354bd1f926eee8465c6a7"
    hash3       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"
    hash4       = "0b5459eb728a278a131a764184d1d333fcd3fc212087b66d9cedce792b1a2d7a"
    hash5       = "c85e7d8e5c1682f21f2d8c9a0e1f6039d583d7eda8276ca9ed3ed381fbde9a7e"

  strings:
    $s1 = "Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s2 = "tion fuck(){return \"Za\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii
    $s3 = "u\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xw\";})(),(function f" ascii
    $s4 = "uck(){return \"TTs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Jo\"" ascii
    $s5 = "fuck(){return \"DHd\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}