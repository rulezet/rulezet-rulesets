rule _20160921_6a795b29889480550a8440815b06fa7d_20160921_70b567ca258b_1890 {
  meta:
    description = "datamaliciousorder - from files 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_70b567ca258b3c505e14f3c712366f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash2       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"

  strings:
    $s1  = "rn \"Av\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(fu" ascii
    $s2  = "fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"I" ascii
    $s3  = "unction fuck(){return \"MUs\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){retu" ascii
    $s4  = ")(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuck(" ascii
    $s5  = "ion fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return " ascii
    $s6  = "eturn \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s7  = "unction fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){retu" ascii
    $s8  = "u\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UXf\";})(),(functio" ascii
    $s9  = "\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Za\";})(),(function f" ascii
    $s10 = "e\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}