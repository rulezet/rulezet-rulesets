rule TTP_XOR_QUAD_CurrentVersionRun_5c4b {
  strings:
    $key_5c4b = { 0f 24 [2] 2b 2a [2] 00 06 [2] 2e 24 [2] 3a 3f [2] 35 25 [2] 2b 38 [2] 29 39 [2] 32 3f [2] 2e 38 [2] 32 17 }

  condition:
    any of them
}