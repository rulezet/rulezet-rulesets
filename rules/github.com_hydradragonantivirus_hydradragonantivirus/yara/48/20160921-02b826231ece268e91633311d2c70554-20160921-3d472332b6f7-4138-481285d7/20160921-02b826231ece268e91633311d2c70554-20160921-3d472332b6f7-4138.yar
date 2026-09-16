rule _20160921_02b826231ece268e91633311d2c70554_20160921_3d472332b6f7_4138 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_ec2541ade561a4750092fda52be6f269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash3       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash4       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"

  strings:
    $s1 = "000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj" ascii
    $s2 = "Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(functi" ascii
    $s3 = "000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XT" ascii
    $s4 = "})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(" ascii
    $s5 = "(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}