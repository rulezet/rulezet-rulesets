rule _20160921_1c739a510b202fd8658c1445b926e28b_20160921_21ea22d345e7_435 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c739a510b202fd8658c1445b926e28b.js, 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_dd42e850834f3af27a08edf609a699b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5e44b6b8f05f9e4eadc507955ef770936acdd360f7dcfe6bb70a36427b04b7"
    hash2       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash3       = "d7708087ab30a8d0d937f9d460512c05c37534c0d3c387bd3e1dd7fcb84fdc58"

  strings:
    $s1  = "{return \"Cd\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s2  = ")(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Yk\";})(),(function fuck" ascii
    $s3  = "function fuck(){return \"DRx\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){re" ascii
    $s4  = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retur" ascii
    $s5  = "function fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){re" ascii
    $s6  = " \"DRx\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"QTc\";})(),(fun" ascii
    $s7  = "return \"MBg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Py\";})()" ascii
    $s8  = ";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"MUs\";})(),(function f" ascii
    $s9  = "XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(functi" ascii
    $s10 = "unction fuck(){return \"Nm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){ret" ascii
    $s11 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"M" ascii
    $s12 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"PDf\";})(" ascii
    $s13 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return " ascii
    $s14 = "k(){return \"Yk\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ve\";}" ascii
    $s15 = "(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){" ascii
    $s16 = " fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IP" ascii
    $s17 = "f\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function " ascii
    $s18 = "ction fuck(){return \"ZWu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s19 = "urn \"Et\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s20 = "(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Xg\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}