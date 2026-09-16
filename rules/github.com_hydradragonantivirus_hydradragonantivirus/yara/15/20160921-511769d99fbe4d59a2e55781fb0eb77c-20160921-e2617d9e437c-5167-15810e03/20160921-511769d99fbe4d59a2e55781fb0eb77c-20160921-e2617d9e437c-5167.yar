rule _20160921_511769d99fbe4d59a2e55781fb0eb77c_20160921_e2617d9e437c_5167 {
  meta:
    description = "datamaliciousorder - from files 20160921_511769d99fbe4d59a2e55781fb0eb77c.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f4a69b097fb3d0d29d7f041be11cd2e8af137bd0ed525674079a1b7de28c7fd"
    hash2       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"

  strings:
    $s1 = " fuck(){return \"MUs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s2 = "on fuck(){return \"Zy\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s3 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"FJs\";})(),(function fuck(" ascii
    $s4 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"YAv\";})(),(function fuck(" ascii
    $s5 = " fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"H" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}