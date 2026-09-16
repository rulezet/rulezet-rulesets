rule _20160921_4855f7b1e1da9c1c5863fa798f27645a_20160921_731724a743a1_3728 {
  meta:
    description = "datamaliciousorder - from files 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_d6dc24b88112bfdeca39a6062c7510f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash2       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash3       = "b22daaadbd25f5bd920609cbc37e7ea10c4cd99c069220697c4c5db594cffee2"

  strings:
    $s1 = "rn \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(fun" ascii
    $s2 = "eturn \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})()," ascii
    $s3 = "){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})" ascii
    $s4 = "KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(funct" ascii
    $s5 = "000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\"" ascii
    $s6 = "){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}