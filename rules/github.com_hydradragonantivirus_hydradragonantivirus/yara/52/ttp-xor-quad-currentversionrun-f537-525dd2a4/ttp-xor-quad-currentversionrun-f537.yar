rule TTP_XOR_QUAD_CurrentVersionRun_f537 {
  strings:
    $key_f537 = { a6 58 [2] 82 56 [2] a9 7a [2] 87 58 [2] 93 43 [2] 9c 59 [2] 82 44 [2] 80 45 [2] 9b 43 [2] 87 44 [2] 9b 6b }

  condition:
    any of them
}