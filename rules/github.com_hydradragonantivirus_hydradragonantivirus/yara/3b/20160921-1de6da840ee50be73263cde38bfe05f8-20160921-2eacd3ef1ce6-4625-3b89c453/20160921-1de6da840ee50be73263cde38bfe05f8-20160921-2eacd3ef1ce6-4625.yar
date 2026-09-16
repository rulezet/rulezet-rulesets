rule _20160921_1de6da840ee50be73263cde38bfe05f8_20160921_2eacd3ef1ce6_4625 {
  meta:
    description = "datamaliciousorder - from files 20160921_1de6da840ee50be73263cde38bfe05f8.js, 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_e985c90f8141417e484ad0056c9b809c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"
    hash2       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash3       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash4       = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"

  strings:
    $s1 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){retur" ascii
    $s2 = "(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s3 = "\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function " ascii
    $s4 = "on f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii
    $s5 = "urn \"Vu\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}