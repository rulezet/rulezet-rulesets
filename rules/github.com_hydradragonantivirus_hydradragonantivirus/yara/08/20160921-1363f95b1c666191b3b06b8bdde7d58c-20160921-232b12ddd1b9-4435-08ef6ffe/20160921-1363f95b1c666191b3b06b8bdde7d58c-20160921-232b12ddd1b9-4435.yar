rule _20160921_1363f95b1c666191b3b06b8bdde7d58c_20160921_232b12ddd1b9_4435 {
  meta:
    description = "datamaliciousorder - from files 20160921_1363f95b1c666191b3b06b8bdde7d58c.js, 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_8b272d3350b65135770a56abfe6a28e0.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa3f648dc04a8b93f29d34ed8ee56d888b7b7469f9b81a0cc95a1d6f7ab8b098"
    hash2       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash3       = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"
    hash4       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"

  strings:
    $s1 = "nction fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){retu" ascii
    $s2 = "rn \"DHd\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(fu" ascii
    $s3 = " fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s4 = "(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s5 = "){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}