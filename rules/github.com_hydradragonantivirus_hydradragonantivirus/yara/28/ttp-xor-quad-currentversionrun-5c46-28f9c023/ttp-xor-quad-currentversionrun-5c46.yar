rule TTP_XOR_QUAD_CurrentVersionRun_5c46 {
  strings:
    $key_5c46 = { 0f 29 [2] 2b 27 [2] 00 0b [2] 2e 29 [2] 3a 32 [2] 35 28 [2] 2b 35 [2] 29 34 [2] 32 32 [2] 2e 35 [2] 32 1a }

  condition:
    any of them
}