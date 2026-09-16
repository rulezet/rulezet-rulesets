rule _20160921_3e5e21af311d364f73107419b54e74e3_20160921_92203c861b27_1478 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash2       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"

  strings:
    $s1  = "urn \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"UEg\";})(),(" ascii
    $s2  = "),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(" ascii
    $s3  = "function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){re" ascii
    $s4  = " f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"" ascii
    $s5  = "nction f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){retu" ascii
    $s6  = "rn \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})(),(fun" ascii
    $s7  = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"HJm\";" ascii
    $s8  = "function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){ret" ascii
    $s9  = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Rh" ascii
    $s10 = "f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GG" ascii
    $s11 = "unction f000(){return \"MDb\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Mt\";})(),(function f000(){retu" ascii
    $s12 = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){ret" ascii
    $s13 = "urn \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Wy\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}