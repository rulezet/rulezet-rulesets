rule _20160921_63a82ecb2e4eb3b0dd878bbec885c469_20160921_ce3c0604d52e_1731 {
  meta:
    description = "datamaliciousorder - from files 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"
    hash2       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"

  strings:
    $s1  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"" ascii
    $s2  = "(){return \"DRx\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"NKq\";}" ascii
    $s3  = "){return \"Wo\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s4  = "n fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Y" ascii
    $s5  = "Qr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(function" ascii
    $s6  = "urn \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MOj\";})(),(" ascii
    $s7  = "turn \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s8  = "n \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Dc\";})(),(fun" ascii
    $s9  = "u\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s10 = "{return \"CTm\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";}" ascii
    $s11 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}