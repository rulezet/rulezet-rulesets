rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_d999dcba53f5_4634 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"

  strings:
    $s1 = "urn \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(fu" ascii
    $s2 = "Gn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function " ascii
    $s3 = "\"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s4 = "ion f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s5 = "nction f000(){return \"KXg\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}