rule _20160921_e2617d9e437c12b61ada4700f8e426b8_20160921_ee6d5c7dc2c0_2578 {
  meta:
    description = "datamaliciousorder - from files 20160921_e2617d9e437c12b61ada4700f8e426b8.js, 20160921_ee6d5c7dc2c03b89ea5ef53aa0c676a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"
    hash2       = "ddd3db3929119812b70ad9f62bd3187b6108d24999c41a8ff5390bc9a60387a3"

  strings:
    $s1 = "){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})" ascii
    $s2 = "ion fuck(){return \"Jo\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return " ascii
    $s3 = "on fuck(){return \"Mw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s4 = "uck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu" ascii
    $s5 = "\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function f" ascii
    $s6 = "We\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s7 = " fuck(){return \"GWo\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s8 = "rn \"To\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}