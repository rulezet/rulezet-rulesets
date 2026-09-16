rule _20160921_346ce24842d4c67049d4ae8a4ef57f0b_20160922_99c635a67f89_3616 {
  meta:
    description = "datamaliciousorder - from files 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash2       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1 = "eturn \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s2 = "f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"R" ascii
    $s3 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"NYh\";})(),(function " ascii
    $s4 = "Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s5 = "return \"Qa\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})()," ascii
    $s6 = "return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}