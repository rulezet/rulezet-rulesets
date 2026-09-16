rule _20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347_20160921_d414cec9501c_4008 {
  meta:
    description = "datamaliciousorder - from files 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"
    hash2       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"

  strings:
    $s1 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){retu" ascii
    $s2 = "ck(){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Xw\";" ascii
    $s3 = "on fuck(){return \"MUs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4 = "Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s5 = "(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){" ascii
    $s6 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}