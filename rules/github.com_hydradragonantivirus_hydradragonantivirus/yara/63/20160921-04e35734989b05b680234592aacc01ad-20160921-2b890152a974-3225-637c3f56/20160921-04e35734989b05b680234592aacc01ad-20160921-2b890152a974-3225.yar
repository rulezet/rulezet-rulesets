rule _20160921_04e35734989b05b680234592aacc01ad_20160921_2b890152a974_3225 {
  meta:
    description = "datamaliciousorder - from files 20160921_04e35734989b05b680234592aacc01ad.js, 20160921_2b890152a974503e2dcd034f2b4084b0.js, 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_4e6afd7ea6614e65fabdc4281ed92b34.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6553e0c768ddf3ba1bc09a83e90e280707f7613c13bcc2b4bae89c9a347ee2f5"
    hash2       = "74075b371da5cc0281ecbcdc311542bcafb1a5daba17f8b3fafc81a88714f625"
    hash3       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash4       = "2af9fdbe6325bb563ca12f506f0bc07133a1951c94c5f0bd5dced26a493d8e18"
    hash5       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"

  strings:
    $s1 = "rn \"DRx\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";})(),(fu" ascii
    $s2 = "})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"KVh\";})(),(function fu" ascii
    $s3 = "ion fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return" ascii
    $s4 = "(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s5 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return" ascii
    $s6 = "eturn \"DRx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"DRx\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}