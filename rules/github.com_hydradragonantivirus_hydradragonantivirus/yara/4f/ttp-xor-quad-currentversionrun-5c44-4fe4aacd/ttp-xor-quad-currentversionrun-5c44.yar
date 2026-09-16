rule TTP_XOR_QUAD_CurrentVersionRun_5c44 {
  strings:
    $key_5c44 = { 0f 2b [2] 2b 25 [2] 00 09 [2] 2e 2b [2] 3a 30 [2] 35 2a [2] 2b 37 [2] 29 36 [2] 32 30 [2] 2e 37 [2] 32 18 }

  condition:
    any of them
}