rule _20160921_d44650cb742ce4feede24ebce4407e1a_20160921_ec2d2710e921_5706 {
  meta:
    description = "datamaliciousorder - from files 20160921_d44650cb742ce4feede24ebce4407e1a.js, 20160921_ec2d2710e9217c2f295a4b410a623d5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"
    hash2       = "efabdabbb3a7d8e1d713826868acadadd9ab03b4cb57f3799d6add11f212fdd9"

  strings:
    $s1 = "OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"KVh\";})(),(funct" ascii
    $s2 = "uck(){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s3 = " fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"" ascii
    $s4 = "nction fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){retu" ascii
    $s5 = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"UXf\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}