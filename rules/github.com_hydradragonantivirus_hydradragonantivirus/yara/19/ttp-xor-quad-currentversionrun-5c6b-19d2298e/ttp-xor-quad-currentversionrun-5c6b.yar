rule TTP_XOR_QUAD_CurrentVersionRun_5c6b {
  strings:
    $key_5c6b = { 0f 04 [2] 2b 0a [2] 00 26 [2] 2e 04 [2] 3a 1f [2] 35 05 [2] 2b 18 [2] 29 19 [2] 32 1f [2] 2e 18 [2] 32 37 }

  condition:
    any of them
}