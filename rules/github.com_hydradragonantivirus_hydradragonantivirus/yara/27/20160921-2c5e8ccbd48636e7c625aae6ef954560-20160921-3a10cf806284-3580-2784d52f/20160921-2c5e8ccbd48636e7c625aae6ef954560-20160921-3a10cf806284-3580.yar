rule _20160921_2c5e8ccbd48636e7c625aae6ef954560_20160921_3a10cf806284_3580 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_3a10cf80628434d9e46f20272ebff11d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash2       = "c217c4eb7bba8a6770bdd6609635a67fc8772b37668310875b4f4f1ff0b472c2"

  strings:
    $s1 = "{return \"MUs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s2 = "ction fuck(){return \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retu" ascii
    $s3 = "})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck" ascii
    $s4 = "){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})" ascii
    $s5 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IP" ascii
    $s6 = "eturn \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}