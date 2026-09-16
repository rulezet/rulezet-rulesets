rule _20160921_232b12ddd1b901389868a9b4ede90a00_20160921_3e1e1d6341df_4726 {
  meta:
    description = "datamaliciousorder - from files 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_3e1e1d6341df1caf923e4b9f79ea9ac3.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash2       = "d858d56d343b97488263af92c96b6bee8f8213dd2aec4d79132b57f04ea3c568"
    hash3       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"

  strings:
    $s1 = "rn \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Oh\";})(),(fu" ascii
    $s2 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){retur" ascii
    $s3 = "(){return \"Ai\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";}" ascii
    $s4 = "uck(){return \"Xg\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug" ascii
    $s5 = "on fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}