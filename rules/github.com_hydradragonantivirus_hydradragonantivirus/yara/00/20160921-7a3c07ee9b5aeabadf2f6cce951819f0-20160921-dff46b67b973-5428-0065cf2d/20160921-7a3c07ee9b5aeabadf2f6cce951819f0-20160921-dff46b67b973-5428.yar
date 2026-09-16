rule _20160921_7a3c07ee9b5aeabadf2f6cce951819f0_20160921_dff46b67b973_5428 {
  meta:
    description = "datamaliciousorder - from files 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash2       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"

  strings:
    $s1 = "return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Qz\";})()" ascii
    $s2 = " f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"" ascii
    $s3 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000()" ascii
    $s4 = "tion f000(){return \"ZIi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return" ascii
    $s5 = "eturn \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}