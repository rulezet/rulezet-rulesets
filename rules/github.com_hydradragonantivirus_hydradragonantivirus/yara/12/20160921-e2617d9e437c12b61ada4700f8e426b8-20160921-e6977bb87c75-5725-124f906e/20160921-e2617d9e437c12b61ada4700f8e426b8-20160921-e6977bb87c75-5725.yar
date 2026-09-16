rule _20160921_e2617d9e437c12b61ada4700f8e426b8_20160921_e6977bb87c75_5725 {
  meta:
    description = "datamaliciousorder - from files 20160921_e2617d9e437c12b61ada4700f8e426b8.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"
    hash2       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"
    hash3       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1 = "(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"We\";})(" ascii
    $s2 = "ion fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return " ascii
    $s3 = "urn \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(fu" ascii
    $s4 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){ret" ascii
    $s5 = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Jh\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}