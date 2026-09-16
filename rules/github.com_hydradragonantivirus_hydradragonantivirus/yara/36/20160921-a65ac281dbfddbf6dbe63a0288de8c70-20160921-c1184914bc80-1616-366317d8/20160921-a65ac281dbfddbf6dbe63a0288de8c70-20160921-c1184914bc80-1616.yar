rule _20160921_a65ac281dbfddbf6dbe63a0288de8c70_20160921_c1184914bc80_1616 {
  meta:
    description = "datamaliciousorder - from files 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash2       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"

  strings:
    $s1  = "(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"RLk\";})(),(function f000" ascii
    $s2  = "000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Lo\"" ascii
    $s3  = "on f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s4  = "n \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s5  = "return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})()" ascii
    $s6  = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return " ascii
    $s7  = "Gn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"SGs\";})(),(functio" ascii
    $s8  = ";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(function f000" ascii
    $s9  = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(fu" ascii
    $s10 = "ction f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000(){retu" ascii
    $s11 = ",(function f000(){return \"IPu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000()" ascii
    $s12 = "n f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"G" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}