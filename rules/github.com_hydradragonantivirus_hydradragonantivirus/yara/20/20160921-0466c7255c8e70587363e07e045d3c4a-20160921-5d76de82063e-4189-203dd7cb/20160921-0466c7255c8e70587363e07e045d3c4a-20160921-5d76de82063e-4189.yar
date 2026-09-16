rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_5d76de82063e_4189 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_5d76de82063e28ac2a0fc9a6ce296761.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"

  strings:
    $s1 = "nction f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){ret" ascii
    $s2 = "Kp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(functio" ascii
    $s3 = " \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(fun" ascii
    $s4 = "ction f000(){return \"MKa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s5 = ",(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}