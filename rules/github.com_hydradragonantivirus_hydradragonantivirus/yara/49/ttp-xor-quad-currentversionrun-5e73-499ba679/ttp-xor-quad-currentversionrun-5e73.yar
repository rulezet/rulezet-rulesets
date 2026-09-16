rule TTP_XOR_QUAD_CurrentVersionRun_5e73 {
  strings:
    $key_5e73 = { 0d 1c [2] 29 12 [2] 02 3e [2] 2c 1c [2] 38 07 [2] 37 1d [2] 29 00 [2] 2b 01 [2] 30 07 [2] 2c 00 [2] 30 2f }

  condition:
    any of them
}