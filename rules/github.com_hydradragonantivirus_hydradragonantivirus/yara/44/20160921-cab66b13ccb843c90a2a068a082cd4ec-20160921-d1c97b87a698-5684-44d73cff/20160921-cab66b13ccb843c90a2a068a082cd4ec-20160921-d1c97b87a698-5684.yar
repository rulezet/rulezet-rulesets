rule _20160921_cab66b13ccb843c90a2a068a082cd4ec_20160921_d1c97b87a698_5684 {
  meta:
    description = "datamaliciousorder - from files 20160921_cab66b13ccb843c90a2a068a082cd4ec.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce3b033b39aaca0b7c9abd0fc5eeb09d24d7096d0a399cebd99f7bd8d574f0d1"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj" ascii
    $s2 = "urn \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(f" ascii
    $s3 = "unction f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii
    $s4 = "){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";}" ascii
    $s5 = "n \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}