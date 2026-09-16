rule _20160921_334dc22c3620386c4119de547e0c0f38_20160921_a39f22c0c39a_834 {
  meta:
    description = "datamaliciousorder - from files 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash2       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"

  strings:
    $s1  = "00(){return \"ZGq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\"" ascii
    $s2  = "0(){return \"Wy\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";}" ascii
    $s3  = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(" ascii
    $s4  = "(){return \"RVb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\"" ascii
    $s5  = "turn \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s6  = "\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f" ascii
    $s7  = ";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f0" ascii
    $s8  = "turn \"Sv\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa\";})(),(" ascii
    $s9  = "urn \"IAa\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Lp\";})(),(f" ascii
    $s10 = ",(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s11 = ")(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yi\";})(),(function f000(" ascii
    $s12 = "function f000(){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s13 = "a\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s14 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})" ascii
    $s15 = "urn \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(" ascii
    $s16 = "Pu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s17 = "rn \"Qj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DYx\";})(),(fu" ascii
    $s18 = "nction f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s19 = ")(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000" ascii
    $s20 = "{return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}