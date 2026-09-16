rule TTP_XOR_QUAD_CurrentVersionRun_f557 {
  strings:
    $key_f557 = { a6 38 [2] 82 36 [2] a9 1a [2] 87 38 [2] 93 23 [2] 9c 39 [2] 82 24 [2] 80 25 [2] 9b 23 [2] 87 24 [2] 9b 0b }

  condition:
    any of them
}