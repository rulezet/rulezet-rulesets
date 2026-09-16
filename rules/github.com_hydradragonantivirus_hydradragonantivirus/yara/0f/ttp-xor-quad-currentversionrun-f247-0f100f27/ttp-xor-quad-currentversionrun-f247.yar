rule TTP_XOR_QUAD_CurrentVersionRun_f247 {
  strings:
    $key_f247 = { a1 28 [2] 85 26 [2] ae 0a [2] 80 28 [2] 94 33 [2] 9b 29 [2] 85 34 [2] 87 35 [2] 9c 33 [2] 80 34 [2] 9c 1b }

  condition:
    any of them
}