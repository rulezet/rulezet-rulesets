rule _20160921_37b52e41aabc93218d864c1665a33610_20160921_3a89132c2088_4921 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_3a89132c20887c3360a3708984b884fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash2       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"

  strings:
    $s1 = "ction f000(){return \"Sv\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return" ascii
    $s2 = "00(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";" ascii
    $s3 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Nv\";})(),(function f000" ascii
    $s4 = "\"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(func" ascii
    $s5 = "})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Wb\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}