rule _20160921_3ec558d1fbbb49dae502fbac7c879ad5_20160921_910cd79d8583_5026 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash2       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"
    hash3       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"

  strings:
    $s1 = "\"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s2 = "tion fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s3 = "\"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s4 = "Pu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(functio" ascii
    $s5 = "urn \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}