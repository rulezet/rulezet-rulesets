rule TTP_XOR_QUAD_CurrentVersionRun_5c65 {
  strings:
    $key_5c65 = { 0f 0a [2] 2b 04 [2] 00 28 [2] 2e 0a [2] 3a 11 [2] 35 0b [2] 2b 16 [2] 29 17 [2] 32 11 [2] 2e 16 [2] 32 39 }

  condition:
    any of them
}