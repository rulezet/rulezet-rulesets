rule TTP_XOR_QUAD_CurrentVersionRun_5c57 {
  strings:
    $key_5c57 = { 0f 38 [2] 2b 36 [2] 00 1a [2] 2e 38 [2] 3a 23 [2] 35 39 [2] 2b 24 [2] 29 25 [2] 32 23 [2] 2e 24 [2] 32 0b }

  condition:
    any of them
}