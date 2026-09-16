rule _20160921_37c1eae8c73482d7ccd62bb1c25f74b0_20160921_6f8e01604e95_4932 {
  meta:
    description = "datamaliciousorder - from files 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_6f8e01604e95009c9405a4a9c31cc901.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash2       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"

  strings:
    $s1 = "QTc\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(functio" ascii
    $s2 = "){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";" ascii
    $s3 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){re" ascii
    $s4 = "ck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj" ascii
    $s5 = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"QTc\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}