rule _20160921_3a10cf80628434d9e46f20272ebff11d_20160921_8881f4de1f94_3654 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a10cf80628434d9e46f20272ebff11d.js, 20160921_8881f4de1f94ec992ad3832b292063a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c217c4eb7bba8a6770bdd6609635a67fc8772b37668310875b4f4f1ff0b472c2"
    hash2       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"

  strings:
    $s1 = " \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s2 = "fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"E" ascii
    $s3 = "tion fuck(){return \"CTm\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return " ascii
    $s4 = "nction fuck(){return \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retur" ascii
    $s5 = "uck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ik" ascii
    $s6 = "urn \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}