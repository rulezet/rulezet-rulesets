rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_37277908f811_2753 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_37277908f8111ad292e17a84927fe01d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"

  strings:
    $s1 = "eturn \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()" ascii
    $s2 = "0(){return \"DNa\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s3 = "Ij\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"IAa\";})(),(functio" ascii
    $s4 = "f000(){return \"Nv\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl" ascii
    $s5 = "turn \"Oh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s6 = " f000(){return \"DNa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s7 = "})(),(function f000(){return \"NYh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}