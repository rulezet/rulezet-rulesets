rule TTP_XOR_QUAD_CurrentVersionRun_6946 {
  strings:
    $key_6946 = { 3a 29 [2] 1e 27 [2] 35 0b [2] 1b 29 [2] 0f 32 [2] 00 28 [2] 1e 35 [2] 1c 34 [2] 07 32 [2] 1b 35 [2] 07 1a }

  condition:
    any of them
}