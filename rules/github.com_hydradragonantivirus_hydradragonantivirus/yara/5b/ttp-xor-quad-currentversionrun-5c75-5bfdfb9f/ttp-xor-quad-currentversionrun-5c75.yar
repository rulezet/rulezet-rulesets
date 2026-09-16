rule TTP_XOR_QUAD_CurrentVersionRun_5c75 {
  strings:
    $key_5c75 = { 0f 1a [2] 2b 14 [2] 00 38 [2] 2e 1a [2] 3a 01 [2] 35 1b [2] 2b 06 [2] 29 07 [2] 32 01 [2] 2e 06 [2] 32 29 }

  condition:
    any of them
}