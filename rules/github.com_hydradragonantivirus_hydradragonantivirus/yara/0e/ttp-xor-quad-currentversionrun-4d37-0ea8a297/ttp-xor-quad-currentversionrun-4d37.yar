rule TTP_XOR_QUAD_CurrentVersionRun_4d37 {
  strings:
    $key_4d37 = { 1e 58 [2] 3a 56 [2] 11 7a [2] 3f 58 [2] 2b 43 [2] 24 59 [2] 3a 44 [2] 38 45 [2] 23 43 [2] 3f 44 [2] 23 6b }

  condition:
    any of them
}