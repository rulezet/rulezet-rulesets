rule TTP_XOR_QUAD_CurrentVersionRun_5c74 {
  strings:
    $key_5c74 = { 0f 1b [2] 2b 15 [2] 00 39 [2] 2e 1b [2] 3a 00 [2] 35 1a [2] 2b 07 [2] 29 06 [2] 32 00 [2] 2e 07 [2] 32 28 }

  condition:
    any of them
}