rule _20160921_52ab3697b827675e3be965f7171e236d_20160921_8644cb559dff_5179 {
  meta:
    description = "datamaliciousorder - from files 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash2       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash3       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"

  strings:
    $s1 = "urn \"Py\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s2 = " fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"" ascii
    $s3 = "urn \"Wo\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s4 = ")(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\";})(),(function fuck" ascii
    $s5 = " fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}