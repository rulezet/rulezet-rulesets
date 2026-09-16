rule TTP_XOR_QUAD_CurrentVersionRun_73e7 {
  strings:
    $key_73e7 = { 20 88 [2] 04 86 [2] 2f aa [2] 01 88 [2] 15 93 [2] 1a 89 [2] 04 94 [2] 06 95 [2] 1d 93 [2] 01 94 [2] 1d bb }

  condition:
    any of them
}