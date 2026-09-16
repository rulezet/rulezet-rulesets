rule TTP_XOR_QUAD_CurrentVersionRun_5c17 {
  strings:
    $key_5c17 = { 0f 78 [2] 2b 76 [2] 00 5a [2] 2e 78 [2] 3a 63 [2] 35 79 [2] 2b 64 [2] 29 65 [2] 32 63 [2] 2e 64 [2] 32 4b }

  condition:
    any of them
}