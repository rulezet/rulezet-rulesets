rule _20160921_164a257da283d5c859dcaffb21bf752c_20160921_3214ea252f2a_4492 {
  meta:
    description = "datamaliciousorder - from files 20160921_164a257da283d5c859dcaffb21bf752c.js, 20160921_3214ea252f2a25e018a03ee43ce952f5.js, 20160921_56567a449e5ae44cd4a4e62bb55e63f3.js, 20160921_a0b892850e7511a70b7c95d4603de0d8.js, 20160921_fb2ccc1a635114bc23ea8a0a8413b110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36edb416a5f8703ead3fb8f8fbb7a0fb98ac21c559eb20558b33460ba9dfc9a0"
    hash2       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"
    hash3       = "e0950a0ccf96b116ed17c3fbaa99325e34f0b717e3e354bd1f926eee8465c6a7"
    hash4       = "0b5459eb728a278a131a764184d1d333fcd3fc212087b66d9cedce792b1a2d7a"
    hash5       = "c85e7d8e5c1682f21f2d8c9a0e1f6039d583d7eda8276ca9ed3ed381fbde9a7e"

  strings:
    $s1 = "turn \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(" ascii
    $s2 = "unction fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii
    $s3 = "){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";}" ascii
    $s4 = "rn \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(fu" ascii
    $s5 = "){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}