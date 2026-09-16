rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_66566a9bbc78_4506 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_86f41d8c83240a68770674107f15f162.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash3       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"

  strings:
    $s1 = "})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000" ascii
    $s2 = "eturn \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s3 = "000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\"" ascii
    $s4 = " \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s5 = "00(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Ml\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}