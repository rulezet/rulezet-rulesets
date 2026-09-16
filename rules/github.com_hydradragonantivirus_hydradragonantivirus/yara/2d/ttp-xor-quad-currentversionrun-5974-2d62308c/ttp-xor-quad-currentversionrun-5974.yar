rule TTP_XOR_QUAD_CurrentVersionRun_5974 {
  strings:
    $key_5974 = { 0a 1b [2] 2e 15 [2] 05 39 [2] 2b 1b [2] 3f 00 [2] 30 1a [2] 2e 07 [2] 2c 06 [2] 37 00 [2] 2b 07 [2] 37 28 }

  condition:
    any of them
}