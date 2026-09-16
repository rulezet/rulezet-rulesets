rule _20160921_42353ce257534ed06a8c73cebdde12dc_20160921_de770f0ed114_5042 {
  meta:
    description = "datamaliciousorder - from files 20160921_42353ce257534ed06a8c73cebdde12dc.js, 20160921_de770f0ed114194a1a9d5e965c4fe675.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"
    hash2       = "57a3f4ba7362a09dfecfe27f6b8517c8290bc04a7020f4bbe4e9200a42655be0"
    hash3       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){r" ascii
    $s2 = "\"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(func" ascii
    $s3 = "ion fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s4 = "nction fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){retur" ascii
    $s5 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}