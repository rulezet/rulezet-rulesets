rule TTP_XOR_QUAD_CurrentVersionRun_f047 {
  strings:
    $key_f047 = { a3 28 [2] 87 26 [2] ac 0a [2] 82 28 [2] 96 33 [2] 99 29 [2] 87 34 [2] 85 35 [2] 9e 33 [2] 82 34 [2] 9e 1b }

  condition:
    any of them
}