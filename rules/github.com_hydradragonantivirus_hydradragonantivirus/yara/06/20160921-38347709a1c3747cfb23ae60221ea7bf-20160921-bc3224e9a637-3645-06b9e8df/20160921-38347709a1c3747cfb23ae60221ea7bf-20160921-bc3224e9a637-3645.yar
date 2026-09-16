rule _20160921_38347709a1c3747cfb23ae60221ea7bf_20160921_bc3224e9a637_3645 {
  meta:
    description = "datamaliciousorder - from files 20160921_38347709a1c3747cfb23ae60221ea7bf.js, 20160921_bc3224e9a637b2113b3de820bcee66c0.js, 20160921_df47c7f57f308287ca344dcc34150b37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39473c48023f5000ce36bdc645860556dc6b5f3b0022f86190a49370f4633bbc"
    hash2       = "65d11827de99ef59cd2cc61d914e235dd2b16ac6b8f4f65f39b8a79dad86ed57"
    hash3       = "dbb4502419f8afb7a2d5fc4186a2c7922701956498b55deb8c27312672415d9c"

  strings:
    $s1 = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(f" ascii
    $s2 = "tion fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii
    $s3 = "y\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function" ascii
    $s4 = ")(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuc" ascii
    $s5 = "ck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug" ascii
    $s6 = " fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}