rule _20160921_13e37e5857b4357c4b5f40a021143101_20160921_2a4c1d98d0b8_1977 {
  meta:
    description = "datamaliciousorder - from files 20160921_13e37e5857b4357c4b5f40a021143101.js, 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd94ae3a0c3b8dadcaba65cdd5f58ebd19d616ac5679af1b7891e5bf26889265"
    hash2       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"

  strings:
    $s1 = ";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f00" ascii
    $s2 = "Ts\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"ZFe\";})(),(functio" ascii
    $s3 = "000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"PT" ascii
    $s4 = "n \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Vj\";})(),(fun" ascii
    $s5 = "(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s6 = "n f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii
    $s7 = "(){return \"PTs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";}" ascii
    $s8 = " \"Vj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s9 = "000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}