rule TTP_XOR_QUAD_CurrentVersionRun_47e4 {
  strings:
    $key_47e4 = { 14 8b [2] 30 85 [2] 1b a9 [2] 35 8b [2] 21 90 [2] 2e 8a [2] 30 97 [2] 32 96 [2] 29 90 [2] 35 97 [2] 29 b8 }

  condition:
    any of them
}