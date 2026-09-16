rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_164a257da283_4152 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_164a257da283d5c859dcaffb21bf752c.js, 20160921_2f8fa7cee8a6f4f78978b7417f3f700e.js, 20160921_56567a449e5ae44cd4a4e62bb55e63f3.js, 20160921_718cbfc32cb1f435745a5a005d3f190b.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js, 20160921_a0b892850e7511a70b7c95d4603de0d8.js, 20160921_acea633b73985995ce9764bf94db0972.js, 20160921_fb2ccc1a635114bc23ea8a0a8413b110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "36edb416a5f8703ead3fb8f8fbb7a0fb98ac21c559eb20558b33460ba9dfc9a0"
    hash3       = "6410122a95cd840a4eef622389d8026475b4f6a156d4b5288cf227165c036c96"
    hash4       = "e0950a0ccf96b116ed17c3fbaa99325e34f0b717e3e354bd1f926eee8465c6a7"
    hash5       = "7611b8615a5a07f89bc6a867e9232ae443f0ff2bb48d960d2254e1390a27fdee"
    hash6       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"
    hash7       = "0b5459eb728a278a131a764184d1d333fcd3fc212087b66d9cedce792b1a2d7a"
    hash8       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"
    hash9       = "c85e7d8e5c1682f21f2d8c9a0e1f6039d583d7eda8276ca9ed3ed381fbde9a7e"

  strings:
    $s1 = "turn \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(f" ascii
    $s2 = ";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuc" ascii
    $s3 = "fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\"" ascii
    $s4 = "(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";}" ascii
    $s5 = "unction fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}