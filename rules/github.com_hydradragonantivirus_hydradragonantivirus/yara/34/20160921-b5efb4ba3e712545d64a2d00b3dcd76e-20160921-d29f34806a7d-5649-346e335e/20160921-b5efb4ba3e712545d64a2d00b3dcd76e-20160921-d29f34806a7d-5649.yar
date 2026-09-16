rule _20160921_b5efb4ba3e712545d64a2d00b3dcd76e_20160921_d29f34806a7d_5649 {
  meta:
    description = "datamaliciousorder - from files 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"
    hash2       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"

  strings:
    $s1 = "n fuck(){return \"Et\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"" ascii
    $s2 = "\"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s3 = "){return \"Ai\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Pc\";})()" ascii
    $s4 = "unction fuck(){return \"Ot\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){ret" ascii
    $s5 = ",(function fuck(){return \"Wo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}