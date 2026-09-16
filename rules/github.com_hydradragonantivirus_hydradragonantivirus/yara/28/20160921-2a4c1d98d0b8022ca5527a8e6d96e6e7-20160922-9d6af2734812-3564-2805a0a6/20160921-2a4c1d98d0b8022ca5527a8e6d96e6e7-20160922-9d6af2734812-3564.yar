rule _20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7_20160922_9d6af2734812_3564 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "0(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";" ascii
    $s2 = "n f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"T" ascii
    $s3 = "eturn \"Ml\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s4 = "n \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(fu" ascii
    $s5 = "return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})()," ascii
    $s6 = ";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}