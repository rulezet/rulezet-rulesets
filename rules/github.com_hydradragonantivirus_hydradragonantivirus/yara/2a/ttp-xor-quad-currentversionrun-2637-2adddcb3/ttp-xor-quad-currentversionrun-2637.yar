rule TTP_XOR_QUAD_CurrentVersionRun_2637 {
  strings:
    $key_2637 = { 75 58 [2] 51 56 [2] 7a 7a [2] 54 58 [2] 40 43 [2] 4f 59 [2] 51 44 [2] 53 45 [2] 48 43 [2] 54 44 [2] 48 6b }

  condition:
    any of them
}