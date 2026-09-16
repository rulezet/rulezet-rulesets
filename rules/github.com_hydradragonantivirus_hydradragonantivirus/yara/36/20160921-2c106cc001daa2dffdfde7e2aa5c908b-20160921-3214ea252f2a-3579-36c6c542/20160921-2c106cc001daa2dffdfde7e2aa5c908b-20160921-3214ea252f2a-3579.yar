rule _20160921_2c106cc001daa2dffdfde7e2aa5c908b_20160921_3214ea252f2a_3579 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c106cc001daa2dffdfde7e2aa5c908b.js, 20160921_3214ea252f2a25e018a03ee43ce952f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca5356b92abf859d45d843749f45e5e06c7d045b4e7ea5d215ab87cdb8c8f66b"
    hash2       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"

  strings:
    $s1 = "ion fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s2 = "return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s3 = "urn \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(" ascii
    $s4 = "ction fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s5 = " \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s6 = "return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}