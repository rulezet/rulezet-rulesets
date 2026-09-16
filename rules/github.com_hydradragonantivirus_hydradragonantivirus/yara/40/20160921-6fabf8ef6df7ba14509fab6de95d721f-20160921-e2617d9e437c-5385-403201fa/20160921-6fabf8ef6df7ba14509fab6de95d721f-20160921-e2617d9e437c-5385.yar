rule _20160921_6fabf8ef6df7ba14509fab6de95d721f_20160921_e2617d9e437c_5385 {
  meta:
    description = "datamaliciousorder - from files 20160921_6fabf8ef6df7ba14509fab6de95d721f.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6962383b3793edac58fef061128f9047afb39eaa645d3f7977a775ceeb02e56"
    hash2       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"

  strings:
    $s1 = "on fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"I" ascii
    $s2 = " \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(fun" ascii
    $s3 = "fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf" ascii
    $s4 = "\"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(functio" ascii
    $s5 = "{return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}