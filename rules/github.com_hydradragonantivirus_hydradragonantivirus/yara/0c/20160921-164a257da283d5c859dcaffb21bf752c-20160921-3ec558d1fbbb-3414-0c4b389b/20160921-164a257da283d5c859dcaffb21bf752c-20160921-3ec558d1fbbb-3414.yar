rule _20160921_164a257da283d5c859dcaffb21bf752c_20160921_3ec558d1fbbb_3414 {
  meta:
    description = "datamaliciousorder - from files 20160921_164a257da283d5c859dcaffb21bf752c.js, 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_56567a449e5ae44cd4a4e62bb55e63f3.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js, 20160921_a0b892850e7511a70b7c95d4603de0d8.js, 20160921_fb2ccc1a635114bc23ea8a0a8413b110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36edb416a5f8703ead3fb8f8fbb7a0fb98ac21c559eb20558b33460ba9dfc9a0"
    hash2       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash3       = "e0950a0ccf96b116ed17c3fbaa99325e34f0b717e3e354bd1f926eee8465c6a7"
    hash4       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"
    hash5       = "0b5459eb728a278a131a764184d1d333fcd3fc212087b66d9cedce792b1a2d7a"
    hash6       = "c85e7d8e5c1682f21f2d8c9a0e1f6039d583d7eda8276ca9ed3ed381fbde9a7e"

  strings:
    $s1 = "k(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj" ascii
    $s2 = "n \"FJs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(f" ascii
    $s3 = "nction fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s4 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Za\";})(),(function fuck(){ret" ascii
    $s5 = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Cd\"" ascii
    $s6 = "return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IRn\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}