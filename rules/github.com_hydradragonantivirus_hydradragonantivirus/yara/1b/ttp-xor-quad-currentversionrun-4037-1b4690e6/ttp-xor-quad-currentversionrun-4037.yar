rule TTP_XOR_QUAD_CurrentVersionRun_4037 {
  strings:
    $key_4037 = { 13 58 [2] 37 56 [2] 1c 7a [2] 32 58 [2] 26 43 [2] 29 59 [2] 37 44 [2] 35 45 [2] 2e 43 [2] 32 44 [2] 2e 6b }

  condition:
    any of them
}