rule TTP_XOR_QUAD_CurrentVersionRun_6837 {
  strings:
    $key_6837 = { 3b 58 [2] 1f 56 [2] 34 7a [2] 1a 58 [2] 0e 43 [2] 01 59 [2] 1f 44 [2] 1d 45 [2] 06 43 [2] 1a 44 [2] 06 6b }

  condition:
    any of them
}