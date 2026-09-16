rule _20160921_98f234a378a6dd4e51c1730a4a700647_20160922_f0d656e55be0_3997 {
  meta:
    description = "datamaliciousorder - from files 20160921_98f234a378a6dd4e51c1730a4a700647.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"
    hash2       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1 = "ction f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){retur" ascii
    $s2 = "turn \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(" ascii
    $s3 = "f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"W" ascii
    $s4 = ",(function f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){" ascii
    $s5 = "0(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";}" ascii
    $s6 = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}