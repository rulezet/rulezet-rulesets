rule TTP_XOR_QUAD_CurrentVersionRun_5c73 {
  strings:
    $key_5c73 = { 0f 1c [2] 2b 12 [2] 00 3e [2] 2e 1c [2] 3a 07 [2] 35 1d [2] 2b 00 [2] 29 01 [2] 32 07 [2] 2e 00 [2] 32 2f }

  condition:
    any of them
}