rule _20160921_8acd2bde0828f30802ece6249f9b9483_20160921_ce3c0604d52e_5517 {
  meta:
    description = "datamaliciousorder - from files 20160921_8acd2bde0828f30802ece6249f9b9483.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"
    hash2       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"

  strings:
    $s1 = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo" ascii
    $s2 = "fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RA" ascii
    $s3 = "o\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function" ascii
    $s4 = "urn \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s5 = " fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"M" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}