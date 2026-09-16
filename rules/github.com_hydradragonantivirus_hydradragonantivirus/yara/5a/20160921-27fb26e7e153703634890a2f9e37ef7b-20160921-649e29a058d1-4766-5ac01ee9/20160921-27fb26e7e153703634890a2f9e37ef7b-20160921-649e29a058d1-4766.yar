rule _20160921_27fb26e7e153703634890a2f9e37ef7b_20160921_649e29a058d1_4766 {
  meta:
    description = "datamaliciousorder - from files 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160921_cff7808833d9e819d4a4f10450848a81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash2       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash3       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"

  strings:
    $s1 = "0(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";}" ascii
    $s2 = ",(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){" ascii
    $s3 = " \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"KXg\";})(),(func" ascii
    $s4 = "unction f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){retur" ascii
    $s5 = "RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}