rule _20160921_940fdd83fcdf499d0ebc071f779bd880_20160921_d44650cb742c_3093 {
  meta:
    description = "datamaliciousorder - from files 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash2       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"

  strings:
    $s1 = "{return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s2 = "(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck()" ascii
    $s3 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return " ascii
    $s4 = "tion fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"We\";})(),(function fuck(){return " ascii
    $s5 = "n \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(fun" ascii
    $s6 = "u\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s7 = "ck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}