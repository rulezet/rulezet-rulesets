rule TTP_XOR_QUAD_CurrentVersionRun_5c77 {
  strings:
    $key_5c77 = { 0f 18 [2] 2b 16 [2] 00 3a [2] 2e 18 [2] 3a 03 [2] 35 19 [2] 2b 04 [2] 29 05 [2] 32 03 [2] 2e 04 [2] 32 2b }

  condition:
    any of them
}