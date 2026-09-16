rule _20160921_3362ac3903fc5c5d2da5d44e3afe884a_20160921_3bce2f31e98c_4887 {
  meta:
    description = "datamaliciousorder - from files 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js, 20160921_3bce2f31e98c152d025886ed17309773.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"
    hash2       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"
    hash3       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"

  strings:
    $s1 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"IPu" ascii
    $s2 = "n \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(fu" ascii
    $s3 = "ion f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"" ascii
    $s4 = "(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000()" ascii
    $s5 = "000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}