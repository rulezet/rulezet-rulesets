rule TTP_XOR_QUAD_CurrentVersionRun_4637 {
  strings:
    $key_4637 = { 15 58 [2] 31 56 [2] 1a 7a [2] 34 58 [2] 20 43 [2] 2f 59 [2] 31 44 [2] 33 45 [2] 28 43 [2] 34 44 [2] 28 6b }

  condition:
    any of them
}