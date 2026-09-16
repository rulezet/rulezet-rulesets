rule _20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477_20160921_b4c84c929547_5512 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_b4c84c92954782bcf19013150a359ec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash2       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"

  strings:
    $s1 = "rn \"Oe\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"BIj\";})(),(f" ascii
    $s2 = "00(){return \"Mt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\"" ascii
    $s3 = "n f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"" ascii
    $s4 = "urn \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s5 = "f000(){return \"WIj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}