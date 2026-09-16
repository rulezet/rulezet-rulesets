rule TTP_XOR_QUAD_CurrentVersionRun_4574 {
  strings:
    $key_4574 = { 16 1b [2] 32 15 [2] 19 39 [2] 37 1b [2] 23 00 [2] 2c 1a [2] 32 07 [2] 30 06 [2] 2b 00 [2] 37 07 [2] 2b 28 }

  condition:
    any of them
}