rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_72beed3cbd32_4236 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_8be5b3aac0a2f47acb168b56c6f880bf.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash3       = "344d7dd8865545f9f4c1045a85547b4140c66621aeedeb02bf60ff4598ff6930"
    hash4       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1 = "on fuck(){return \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"" ascii
    $s2 = "rn \"We\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s3 = "){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DWe\";})" ascii
    $s4 = "Qr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"ZVi\";})(),(functio" ascii
    $s5 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}