rule _20160921_346ce24842d4c67049d4ae8a4ef57f0b_20160921_a3256642bcc1_1110 {
  meta:
    description = "datamaliciousorder - from files 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash2       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"

  strings:
    $s1  = " \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s2  = "unction f000(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){retu" ascii
    $s3  = "Nv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s4  = "rn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DAp\";})(),(f" ascii
    $s5  = "(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\"" ascii
    $s6  = ")(),(function f000(){return \"MOc\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s7  = "00(){return \"Br\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Br\";" ascii
    $s8  = "g\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f" ascii
    $s9  = "return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})" ascii
    $s10 = "n f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"M" ascii
    $s11 = "urn \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(f" ascii
    $s12 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Tb\";})(),(funct" ascii
    $s13 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Yv\";})" ascii
    $s14 = "tion f000(){return \"MBb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return" ascii
    $s15 = ",(function f000(){return \"Vj\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYs\";})(),(function f000(){" ascii
    $s16 = "eturn \"Tb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})()" ascii
    $s17 = "nction f000(){return \"TKp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}