rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_a3256642bcc1_2712 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"

  strings:
    $s1 = "function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){r" ascii
    $s2 = "\"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Qa\";})(),(func" ascii
    $s3 = ";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DIa\";})(),(function f0" ascii
    $s4 = "rn \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(fu" ascii
    $s5 = "DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(funct" ascii
    $s6 = "eturn \"Uo\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})()," ascii
    $s7 = "){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"MMz\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}