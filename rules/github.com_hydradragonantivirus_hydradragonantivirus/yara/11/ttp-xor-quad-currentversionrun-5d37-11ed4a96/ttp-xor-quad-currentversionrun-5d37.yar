rule TTP_XOR_QUAD_CurrentVersionRun_5d37 {
  strings:
    $key_5d37 = { 0e 58 [2] 2a 56 [2] 01 7a [2] 2f 58 [2] 3b 43 [2] 34 59 [2] 2a 44 [2] 28 45 [2] 33 43 [2] 2f 44 [2] 33 6b }

  condition:
    any of them
}