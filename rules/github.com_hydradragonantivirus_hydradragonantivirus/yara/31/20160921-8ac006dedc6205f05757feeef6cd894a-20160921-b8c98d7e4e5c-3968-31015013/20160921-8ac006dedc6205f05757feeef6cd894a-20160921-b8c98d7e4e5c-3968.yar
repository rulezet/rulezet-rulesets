rule _20160921_8ac006dedc6205f05757feeef6cd894a_20160921_b8c98d7e4e5c_3968 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash2       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"

  strings:
    $s1 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f0" ascii
    $s2 = "tion f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s3 = "000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go" ascii
    $s4 = "v\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function" ascii
    $s5 = "function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){ret" ascii
    $s6 = "{return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}