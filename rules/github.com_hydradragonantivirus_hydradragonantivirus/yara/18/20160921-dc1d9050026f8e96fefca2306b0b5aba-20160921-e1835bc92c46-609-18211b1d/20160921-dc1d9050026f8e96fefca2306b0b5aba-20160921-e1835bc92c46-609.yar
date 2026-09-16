rule _20160921_dc1d9050026f8e96fefca2306b0b5aba_20160921_e1835bc92c46_609 {
  meta:
    description = "datamaliciousorder - from files 20160921_dc1d9050026f8e96fefca2306b0b5aba.js, 20160921_e1835bc92c4604db194bc49df621cade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"
    hash2       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"

  strings:
    $s1  = "f000(){return \"PTi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"G" ascii
    $s2  = "unction f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s3  = "nction f000(){return \"SEo\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"MDb\";})(),(function f000(){retu" ascii
    $s4  = "q\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(functio" ascii
    $s5  = "function f000(){return \"RLk\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){r" ascii
    $s6  = "00(){return \"Oe\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RVb\"" ascii
    $s7  = "function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Nv\";})(),(function f000(){ret" ascii
    $s8  = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"" ascii
    $s9  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return" ascii
    $s10 = "function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mc\";})(),(function f000(){ret" ascii
    $s11 = "unction f000(){return \"Yz\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Rh\";})(),(function f000(){retur" ascii
    $s12 = "Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Km\";})(),(functio" ascii
    $s13 = "ction f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return" ascii
    $s14 = ";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"MDb\";})(),(function f00" ascii
    $s15 = "eturn \"BQb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZFe\";})()" ascii
    $s16 = "n f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"" ascii
    $s17 = "unction f000(){return \"SGs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})(),(function f000(){ret" ascii
    $s18 = "b\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s19 = "){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";}" ascii
    $s20 = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}