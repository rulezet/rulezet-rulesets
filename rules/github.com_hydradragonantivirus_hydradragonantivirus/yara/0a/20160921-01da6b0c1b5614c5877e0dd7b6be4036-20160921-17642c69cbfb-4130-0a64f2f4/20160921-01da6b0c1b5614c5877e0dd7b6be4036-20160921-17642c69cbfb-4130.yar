rule _20160921_01da6b0c1b5614c5877e0dd7b6be4036_20160921_17642c69cbfb_4130 {
  meta:
    description = "datamaliciousorder - from files 20160921_01da6b0c1b5614c5877e0dd7b6be4036.js, 20160921_17642c69cbfb276056f3695ae22dad4c.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da941f7d098e0926acf7ad9efedc9f91495115fc83f288580eba79e44574693"
    hash2       = "4cdbf9fba4e3fec424cf182fd21fa3c400b0649ca09f140375a47df12248955c"
    hash3       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"

  strings:
    $s1 = "\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function" ascii
    $s2 = "turn \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})()," ascii
    $s3 = ")(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s4 = "})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"MOj\";})(),(function fu" ascii
    $s5 = "{return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}