rule _20160921_5775da34d70f97a2d7aa3296f909af35_20160921_6d18600f3019_5223 {
  meta:
    description = "datamaliciousorder - from files 20160921_5775da34d70f97a2d7aa3296f909af35.js, 20160921_6d18600f3019656b0ab414a3d1a69ddb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"
    hash2       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"

  strings:
    $s1 = "on f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2 = "000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\"" ascii
    $s3 = "),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii
    $s4 = "eturn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})()" ascii
    $s5 = "Pt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}