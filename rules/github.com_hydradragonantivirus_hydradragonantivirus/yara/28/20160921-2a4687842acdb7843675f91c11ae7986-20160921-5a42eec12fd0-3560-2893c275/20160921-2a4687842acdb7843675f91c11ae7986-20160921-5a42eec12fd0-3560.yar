rule _20160921_2a4687842acdb7843675f91c11ae7986_20160921_5a42eec12fd0_3560 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_dcd6ef8585af301daafce3419ba14724.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash2       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash3       = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash4       = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"
    hash5       = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"

  strings:
    $s1 = "on fuck(){return \"XCr\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s2 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){ret" ascii
    $s3 = "function fuck(){return \"UXf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){r" ascii
    $s4 = "{return \"Jh\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})" ascii
    $s5 = "fuck(){return \"SUi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"D" ascii
    $s6 = "rn \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Zy\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}