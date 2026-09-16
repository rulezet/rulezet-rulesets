rule _20160921_0550bef558fba79f944112d34861e4ec_20160922_0d54e6d044b3_1772 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"

  strings:
    $s1  = "nction f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mc\";})(),(function f000(){retur" ascii
    $s2  = "00(){return \"PTi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn" ascii
    $s3  = "nction f000(){return \"RLk\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){ret" ascii
    $s4  = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"IAa\";})()" ascii
    $s5  = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Wy\";})(),(function " ascii
    $s6  = "){return \"RLk\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s7  = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"" ascii
    $s8  = "\"Sv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s9  = "0(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";" ascii
    $s10 = "a\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}