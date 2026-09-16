rule _20160921_3a10cf80628434d9e46f20272ebff11d_20160921_a96b471e778a_4959 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a10cf80628434d9e46f20272ebff11d.js, 20160921_a96b471e778a8101c168e06727d930fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c217c4eb7bba8a6770bdd6609635a67fc8772b37668310875b4f4f1ff0b472c2"
    hash2       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"

  strings:
    $s1 = " \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(fu" ascii
    $s2 = "fuck(){return \"XCr\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IP" ascii
    $s3 = "k(){return \"Xw\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";" ascii
    $s4 = " fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IR" ascii
    $s5 = "ion fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}