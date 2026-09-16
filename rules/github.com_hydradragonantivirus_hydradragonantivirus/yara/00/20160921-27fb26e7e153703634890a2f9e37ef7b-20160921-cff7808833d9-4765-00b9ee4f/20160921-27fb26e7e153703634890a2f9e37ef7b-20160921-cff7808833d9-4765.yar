rule _20160921_27fb26e7e153703634890a2f9e37ef7b_20160921_cff7808833d9_4765 {
  meta:
    description = "datamaliciousorder - from files 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_cff7808833d9e819d4a4f10450848a81.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash2       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"
    hash3       = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"

  strings:
    $s1 = "(function f000(){return \"DNa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){r" ascii
    $s2 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s3 = "rn \"Mc\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(fu" ascii
    $s4 = ",(function f000(){return \"ZIi\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s5 = " f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}