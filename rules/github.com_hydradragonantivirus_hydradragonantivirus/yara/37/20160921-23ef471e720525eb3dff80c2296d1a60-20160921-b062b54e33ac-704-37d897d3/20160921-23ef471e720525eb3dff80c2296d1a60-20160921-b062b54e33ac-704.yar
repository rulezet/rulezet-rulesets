rule _20160921_23ef471e720525eb3dff80c2296d1a60_20160921_b062b54e33ac_704 {
  meta:
    description = "datamaliciousorder - from files 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_b062b54e33ac394b0c1a389b161f5cb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash2       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"

  strings:
    $s1  = " f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"G" ascii
    $s2  = "n \"Ml\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(func" ascii
    $s3  = "return \"Qa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})()," ascii
    $s4  = "rn \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s5  = ")(),(function f000(){return \"Oe\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s6  = ",(function f000(){return \"RVb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OMd\";})(),(function f000(){" ascii
    $s7  = "(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Do\";})(),(function f000(" ascii
    $s8  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s9  = "0(){return \"IPu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\"" ascii
    $s10 = "{return \"OUx\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(" ascii
    $s11 = "{return \"QDg\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"QDg\";}" ascii
    $s12 = "turn \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(f" ascii
    $s13 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"UEg\";})(),(function" ascii
    $s14 = "f000(){return \"Sv\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa" ascii
    $s15 = "turn \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})()" ascii
    $s16 = " f000(){return \"Oh\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn" ascii
    $s17 = "Ka\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s18 = "return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(" ascii
    $s19 = "00(){return \"IAa\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Lp\"" ascii
    $s20 = "nction f000(){return \"Wy\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}