rule TTP_XOR_QUAD_CurrentVersionRun_f257 {
  strings:
    $key_f257 = { a1 38 [2] 85 36 [2] ae 1a [2] 80 38 [2] 94 23 [2] 9b 39 [2] 85 24 [2] 87 25 [2] 9c 23 [2] 80 24 [2] 9c 0b }

  condition:
    any of them
}