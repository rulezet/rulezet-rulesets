rule _20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477_20160921_d999dcba53f5_5513 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash2       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"

  strings:
    $s1 = "\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f" ascii
    $s2 = "on f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"" ascii
    $s3 = "nction f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii
    $s4 = "ction f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){retur" ascii
    $s5 = "0(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}