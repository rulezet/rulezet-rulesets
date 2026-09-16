rule TTP_XOR_QUAD_CurrentVersionRun_7346 {
  strings:
    $key_7346 = { 20 29 [2] 04 27 [2] 2f 0b [2] 01 29 [2] 15 32 [2] 1a 28 [2] 04 35 [2] 06 34 [2] 1d 32 [2] 01 35 [2] 1d 1a }

  condition:
    any of them
}