rule TTP_XOR_QUAD_CurrentVersionRun_5637 {
  strings:
    $key_5637 = { 05 58 [2] 21 56 [2] 0a 7a [2] 24 58 [2] 30 43 [2] 3f 59 [2] 21 44 [2] 23 45 [2] 38 43 [2] 24 44 [2] 38 6b }

  condition:
    any of them
}