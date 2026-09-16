rule _20160921_18eedffe02de43ba2ee494451deba790_20160921_1e5a9eb0eb0b_3446 {
  meta:
    description = "datamaliciousorder - from files 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js, 20160921_65ff2a70ce98d58243fbbdf4849b9c40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash2       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash3       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"
    hash4       = "4be01014513bc9c23e14a62953fb7d9f955467208a844109b10c685b1f9c4f29"

  strings:
    $s1 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg" ascii
    $s2 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Mw\";})(),(function fuck()" ascii
    $s3 = "(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Wo\";" ascii
    $s4 = "nction fuck(){return \"XHj\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s5 = "Pu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Mw\";})(),(functio" ascii
    $s6 = "\"TTs\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}