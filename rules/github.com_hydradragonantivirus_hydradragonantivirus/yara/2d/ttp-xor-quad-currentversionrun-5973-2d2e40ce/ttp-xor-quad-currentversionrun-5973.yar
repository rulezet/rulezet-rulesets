rule TTP_XOR_QUAD_CurrentVersionRun_5973 {
  strings:
    $key_5973 = { 0a 1c [2] 2e 12 [2] 05 3e [2] 2b 1c [2] 3f 07 [2] 30 1d [2] 2e 00 [2] 2c 01 [2] 37 07 [2] 2b 00 [2] 37 2f }

  condition:
    any of them
}