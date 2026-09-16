rule _20160921_2a4687842acdb7843675f91c11ae7986_20160921_8881f4de1f94_4791 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_8881f4de1f94ec992ad3832b292063a8.js, 20160921_8be5b3aac0a2f47acb168b56c6f880bf.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash2       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"
    hash3       = "344d7dd8865545f9f4c1045a85547b4140c66621aeedeb02bf60ff4598ff6930"
    hash4       = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"

  strings:
    $s1 = "fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"M" ascii
    $s2 = " \"EHo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(func" ascii
    $s3 = "(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){" ascii
    $s4 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"" ascii
    $s5 = "{return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}