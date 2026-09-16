rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_802181e3d75c_3382 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_802181e3d75c3e2d045cebba97849683.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"

  strings:
    $s1 = "(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000()" ascii
    $s2 = " f000(){return \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"D" ascii
    $s3 = "urn \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})()," ascii
    $s4 = "n f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"SEo\";})(),(function f000(){return " ascii
    $s5 = "(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";" ascii
    $s6 = ")(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}