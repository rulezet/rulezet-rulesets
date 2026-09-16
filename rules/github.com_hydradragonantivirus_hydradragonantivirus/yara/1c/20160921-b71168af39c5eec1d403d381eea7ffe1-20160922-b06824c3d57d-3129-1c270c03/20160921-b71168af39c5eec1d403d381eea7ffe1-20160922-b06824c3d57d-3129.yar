rule _20160921_b71168af39c5eec1d403d381eea7ffe1_20160922_b06824c3d57d_3129 {
  meta:
    description = "datamaliciousorder - from files 20160921_b71168af39c5eec1d403d381eea7ffe1.js, 20160922_b06824c3d57db547b98db8d6b10525d0.js, 20160922_ddc158d1b0906f773c8ee4447daa25e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8811edeb74999e8dd226f7fa9d7963ccfc998904ecb9474d036376253dc6fde"
    hash2       = "73bcfec2ac113640d73b2ea0f0c348d7bc7d672d6be74cb4398f8669b599694b"
    hash3       = "da7f290c48869e8adc8a27e6344a762283ddaa55eae77000c5439a118d259a98"

  strings:
    $s1 = "0(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";" ascii
    $s2 = "nction f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii
    $s3 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return " ascii
    $s4 = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})()" ascii
    $s5 = "n f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"" ascii
    $s6 = "function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){re" ascii
    $s7 = "GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}