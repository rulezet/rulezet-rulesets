rule _20160921_6a795b29889480550a8440815b06fa7d_20160921_fc08be0621d4_5349 {
  meta:
    description = "datamaliciousorder - from files 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash2       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = "){return \"Av\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s2 = "k(){return \"Xw\";})(),(function fuck(){return \"Az\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"DHd\";" ascii
    $s3 = "return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"ZVi\";})(" ascii
    $s4 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Wo\";})(),(functi" ascii
    $s5 = "),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}