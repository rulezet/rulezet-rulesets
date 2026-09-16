rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_85f2776f4fe6_881 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_85f2776f4fe640d2373f51ddbc697659.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "0604503e68d6aa73ca3bbdb29b958ea47ad4c81b2f77ad9db2b0e8467b1c870d"

  strings:
    $s1  = "fuck(){return \"CTm\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Dc" ascii
    $s2  = "\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"ZVi\";})(),(function f" ascii
    $s3  = "(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(" ascii
    $s4  = "fuck(){return \"MIl\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"G" ascii
    $s5  = "tion fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retur" ascii
    $s6  = "})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck" ascii
    $s7  = "eturn \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})()," ascii
    $s8  = "ck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\"" ascii
    $s9  = "})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Ai\";})(),(function fuc" ascii
    $s10 = "})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuc" ascii
    $s11 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"" ascii
    $s12 = "n \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s13 = "){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xg\";})" ascii
    $s14 = "),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"MIl\";})(),(function fuck(" ascii
    $s15 = " fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DR" ascii
    $s16 = "(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ot\";})" ascii
    $s17 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return " ascii
    $s18 = "eturn \"MIl\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s19 = "),(function fuck(){return \"IRn\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XFd\";})(),(function fuck(" ascii
    $s20 = "rn \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}