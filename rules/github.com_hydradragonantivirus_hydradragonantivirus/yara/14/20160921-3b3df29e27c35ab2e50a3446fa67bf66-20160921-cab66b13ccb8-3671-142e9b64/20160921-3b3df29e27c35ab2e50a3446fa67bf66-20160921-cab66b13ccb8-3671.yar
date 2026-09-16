rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_cab66b13ccb8_3671 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_cab66b13ccb843c90a2a068a082cd4ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "ce3b033b39aaca0b7c9abd0fc5eeb09d24d7096d0a399cebd99f7bd8d574f0d1"

  strings:
    $s1 = "z\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s2 = "){return \"Vj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";}" ascii
    $s3 = "nction f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){ret" ascii
    $s4 = "Ts\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s5 = "(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Vj\";}" ascii
    $s6 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYx\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}