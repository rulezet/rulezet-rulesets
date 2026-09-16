rule _20160921_7e15ac2755366d4644a83de8ec9c1a47_20160921_d44650cb742c_3939 {
  meta:
    description = "datamaliciousorder - from files 20160921_7e15ac2755366d4644a83de8ec9c1a47.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97eaf7c50f22bfc94f97a02e5e83a8f1fb3583717fb9f4a6666ae882ea4d6f55"
    hash2       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"

  strings:
    $s1 = "turn \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s2 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s3 = "uck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"LG" ascii
    $s4 = "{return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})" ascii
    $s5 = "\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xw\";})(),(function f" ascii
    $s6 = "(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}