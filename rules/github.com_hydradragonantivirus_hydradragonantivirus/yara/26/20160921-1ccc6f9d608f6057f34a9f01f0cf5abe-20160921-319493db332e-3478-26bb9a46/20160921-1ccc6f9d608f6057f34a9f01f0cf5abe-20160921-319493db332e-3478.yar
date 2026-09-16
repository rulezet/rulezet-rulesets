rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_319493db332e_3478 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_f1cc02f488792b7161849f8d15549315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash3       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash4       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"

  strings:
    $s1 = "{return \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(" ascii
    $s2 = "\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s3 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){retu" ascii
    $s4 = "){return \"PTi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";" ascii
    $s5 = "ion f000(){return \"RLk\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return" ascii
    $s6 = ")(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Wy\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}