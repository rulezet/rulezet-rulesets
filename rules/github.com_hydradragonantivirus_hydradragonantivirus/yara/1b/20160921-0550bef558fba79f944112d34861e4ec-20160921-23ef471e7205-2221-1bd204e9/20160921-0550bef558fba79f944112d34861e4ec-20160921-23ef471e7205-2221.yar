rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_23ef471e7205_2221 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash3       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"

  strings:
    $s1 = "){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Km\";}" ascii
    $s2 = "unction f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){ret" ascii
    $s3 = "00(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Lp\"" ascii
    $s4 = "Vb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(functio" ascii
    $s5 = "){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SEo\";})" ascii
    $s6 = "on f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Km\";})(),(function f000(){return " ascii
    $s7 = "eturn \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs\";})()" ascii
    $s8 = "on f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}