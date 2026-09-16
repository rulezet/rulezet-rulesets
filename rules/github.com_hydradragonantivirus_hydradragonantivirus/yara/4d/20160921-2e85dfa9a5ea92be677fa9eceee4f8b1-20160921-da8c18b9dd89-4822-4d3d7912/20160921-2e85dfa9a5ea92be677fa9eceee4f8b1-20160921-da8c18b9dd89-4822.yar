rule _20160921_2e85dfa9a5ea92be677fa9eceee4f8b1_20160921_da8c18b9dd89_4822 {
  meta:
    description = "datamaliciousorder - from files 20160921_2e85dfa9a5ea92be677fa9eceee4f8b1.js, 20160921_da8c18b9dd89b42c83c09338a42522db.js, 20160921_ecd98b74e6a52b1227b09228f92cb495.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd958e388f97aa8b73e103ada622a36250446b5740c2e70d0bf844240c0968c2"
    hash2       = "4541906a912293fb2fd3b2f0762e5641f73d401239307230b5fc4ae411a1c4f0"
    hash3       = "8930637b40db8c97df91bff2cf5b4021d0bcb2f6a204f27249176fe3d6d4120e"

  strings:
    $s1 = "n fuck(){return \"Vf\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"" ascii
    $s2 = "\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function " ascii
    $s3 = "Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s4 = "tion fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){retur" ascii
    $s5 = "return \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}