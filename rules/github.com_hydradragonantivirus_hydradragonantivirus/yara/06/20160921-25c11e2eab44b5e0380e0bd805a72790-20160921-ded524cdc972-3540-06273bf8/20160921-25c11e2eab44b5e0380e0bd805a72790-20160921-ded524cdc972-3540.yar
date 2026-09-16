rule _20160921_25c11e2eab44b5e0380e0bd805a72790_20160921_ded524cdc972_3540 {
  meta:
    description = "datamaliciousorder - from files 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash2       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = "(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii
    $s2 = ")(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(" ascii
    $s3 = "){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})" ascii
    $s4 = "00(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\"" ascii
    $s5 = "tion f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s6 = "(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}