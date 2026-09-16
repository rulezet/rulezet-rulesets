rule TTP_XOR_QUAD_CurrentVersionRun_4573 {
  strings:
    $key_4573 = { 16 1c [2] 32 12 [2] 19 3e [2] 37 1c [2] 23 07 [2] 2c 1d [2] 32 00 [2] 30 01 [2] 2b 07 [2] 37 00 [2] 2b 2f }

  condition:
    any of them
}