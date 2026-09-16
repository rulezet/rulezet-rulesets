rule _20160921_b5efb4ba3e712545d64a2d00b3dcd76e_20160921_d72e05128386_3127 {
  meta:
    description = "datamaliciousorder - from files 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"
    hash2       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"

  strings:
    $s1 = "urn \"Av\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s2 = "IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Za\";})(),(function" ascii
    $s3 = "Ld\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s4 = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"X" ascii
    $s5 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Wo\";})(),(function fuck" ascii
    $s6 = "DHd\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xw\";})(),(functio" ascii
    $s7 = " \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"KVh\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}