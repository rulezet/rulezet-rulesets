rule _20160921_bc3224e9a637b2113b3de820bcee66c0_20160921_bfdb187f27d1_5661 {
  meta:
    description = "datamaliciousorder - from files 20160921_bc3224e9a637b2113b3de820bcee66c0.js, 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js, 20160921_df47c7f57f308287ca344dcc34150b37.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65d11827de99ef59cd2cc61d914e235dd2b16ac6b8f4f65f39b8a79dad86ed57"
    hash2       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"
    hash3       = "dbb4502419f8afb7a2d5fc4186a2c7922701956498b55deb8c27312672415d9c"
    hash4       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1 = "k(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LLv\"" ascii
    $s2 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){re" ascii
    $s3 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return" ascii
    $s4 = "eturn \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s5 = "{return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}