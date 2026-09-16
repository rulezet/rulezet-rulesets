rule _20160921_25c11e2eab44b5e0380e0bd805a72790_20160921_3e5e21af311d_4749 {
  meta:
    description = "datamaliciousorder - from files 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_6b34f0b83cb5d89ac574db511a389f02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash2       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash3       = "2483c88a0836510cd8b6af7b5d26f30c64147663cbbe75188bd12c828f642afa"

  strings:
    $s1 = "(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";}" ascii
    $s2 = "0(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKl" ascii
    $s3 = "){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})" ascii
    $s4 = "function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s5 = "\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}