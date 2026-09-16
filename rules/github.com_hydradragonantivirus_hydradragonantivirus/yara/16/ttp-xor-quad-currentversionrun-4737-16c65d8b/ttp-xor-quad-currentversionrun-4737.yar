rule TTP_XOR_QUAD_CurrentVersionRun_4737 {
  strings:
    $key_4737 = { 14 58 [2] 30 56 [2] 1b 7a [2] 35 58 [2] 21 43 [2] 2e 59 [2] 30 44 [2] 32 45 [2] 29 43 [2] 35 44 [2] 29 6b }

  condition:
    any of them
}