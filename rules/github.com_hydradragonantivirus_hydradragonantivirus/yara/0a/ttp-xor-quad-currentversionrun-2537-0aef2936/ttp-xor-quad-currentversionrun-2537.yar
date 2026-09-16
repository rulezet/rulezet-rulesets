rule TTP_XOR_QUAD_CurrentVersionRun_2537 {
  strings:
    $key_2537 = { 76 58 [2] 52 56 [2] 79 7a [2] 57 58 [2] 43 43 [2] 4c 59 [2] 52 44 [2] 50 45 [2] 4b 43 [2] 57 44 [2] 4b 6b }

  condition:
    any of them
}