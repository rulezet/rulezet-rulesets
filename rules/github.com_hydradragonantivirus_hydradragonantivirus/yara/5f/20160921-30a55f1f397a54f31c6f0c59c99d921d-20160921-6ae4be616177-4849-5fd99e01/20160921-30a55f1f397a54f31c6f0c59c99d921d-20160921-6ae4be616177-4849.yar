rule _20160921_30a55f1f397a54f31c6f0c59c99d921d_20160921_6ae4be616177_4849 {
  meta:
    description = "datamaliciousorder - from files 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js, 20160921_d56a785468c6ab02ba1f7ee3a5eadcdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash2       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"
    hash3       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"
    hash4       = "d5ca39f97274b051212868ee58d01e745bb87d0a12198dfdfbeb7c3965cbf540"

  strings:
    $s1 = "rn \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(" ascii
    $s2 = "(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(" ascii
    $s3 = " fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s4 = "fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"U" ascii
    $s5 = "n \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}