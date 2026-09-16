rule _20160921_3214ea252f2a25e018a03ee43ce952f5_20160921_35d4c12af7a9_4862 {
  meta:
    description = "datamaliciousorder - from files 20160921_3214ea252f2a25e018a03ee43ce952f5.js, 20160921_35d4c12af7a9481959a41a055c396673.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"
    hash2       = "1c2412951fad30bb8b34aca279acd07c03a437936261b0d90334331b98cf1e99"
    hash3       = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"

  strings:
    $s1 = "k(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s2 = "IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(funct" ascii
    $s3 = "Us\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr\";})(),(functi" ascii
    $s4 = "function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){re" ascii
    $s5 = "(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}