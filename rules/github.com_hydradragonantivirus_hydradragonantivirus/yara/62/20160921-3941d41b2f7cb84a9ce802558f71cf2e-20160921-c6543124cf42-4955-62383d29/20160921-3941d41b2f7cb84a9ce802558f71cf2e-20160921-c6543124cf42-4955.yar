rule _20160921_3941d41b2f7cb84a9ce802558f71cf2e_20160921_c6543124cf42_4955 {
  meta:
    description = "datamaliciousorder - from files 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash2       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash3       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"
    hash4       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"

  strings:
    $s1 = "ion f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s2 = "urn \"Rh\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s3 = "),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s4 = " f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii
    $s5 = "n \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}