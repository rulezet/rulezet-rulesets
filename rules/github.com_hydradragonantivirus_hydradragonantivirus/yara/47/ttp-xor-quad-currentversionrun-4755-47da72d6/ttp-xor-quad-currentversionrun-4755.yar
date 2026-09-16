rule TTP_XOR_QUAD_CurrentVersionRun_4755 {
  strings:
    $key_4755 = { 14 3a [2] 30 34 [2] 1b 18 [2] 35 3a [2] 21 21 [2] 2e 3b [2] 30 26 [2] 32 27 [2] 29 21 [2] 35 26 [2] 29 09 }

  condition:
    any of them
}