rule TTP_XOR_QUAD_CurrentVersionRun_4773 {
  strings:
    $key_4773 = { 14 1c [2] 30 12 [2] 1b 3e [2] 35 1c [2] 21 07 [2] 2e 1d [2] 30 00 [2] 32 01 [2] 29 07 [2] 35 00 [2] 29 2f }

  condition:
    any of them
}