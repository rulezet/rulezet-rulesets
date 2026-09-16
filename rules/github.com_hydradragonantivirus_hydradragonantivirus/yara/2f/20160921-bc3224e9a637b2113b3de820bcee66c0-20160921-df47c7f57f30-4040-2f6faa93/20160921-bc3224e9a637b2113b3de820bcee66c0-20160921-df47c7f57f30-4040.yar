rule _20160921_bc3224e9a637b2113b3de820bcee66c0_20160921_df47c7f57f30_4040 {
  meta:
    description = "datamaliciousorder - from files 20160921_bc3224e9a637b2113b3de820bcee66c0.js, 20160921_df47c7f57f308287ca344dcc34150b37.js, 20160921_ee6d5c7dc2c03b89ea5ef53aa0c676a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65d11827de99ef59cd2cc61d914e235dd2b16ac6b8f4f65f39b8a79dad86ed57"
    hash2       = "dbb4502419f8afb7a2d5fc4186a2c7922701956498b55deb8c27312672415d9c"
    hash3       = "ddd3db3929119812b70ad9f62bd3187b6108d24999c41a8ff5390bc9a60387a3"

  strings:
    $s1 = "eturn \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(" ascii
    $s2 = "),(function fuck(){return \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(" ascii
    $s3 = "{return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(" ascii
    $s4 = "ion fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return" ascii
    $s6 = "ck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}