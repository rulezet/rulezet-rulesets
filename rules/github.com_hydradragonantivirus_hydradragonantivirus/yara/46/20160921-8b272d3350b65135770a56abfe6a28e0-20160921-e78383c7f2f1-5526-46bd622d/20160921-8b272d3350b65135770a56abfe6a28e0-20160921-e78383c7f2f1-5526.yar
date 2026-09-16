rule _20160921_8b272d3350b65135770a56abfe6a28e0_20160921_e78383c7f2f1_5526 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b272d3350b65135770a56abfe6a28e0.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"
    hash2       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"

  strings:
    $s1 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return" ascii
    $s2 = " fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"G" ascii
    $s3 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug" ascii
    $s4 = "unction fuck(){return \"EHo\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii
    $s5 = "{return \"GNm\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}