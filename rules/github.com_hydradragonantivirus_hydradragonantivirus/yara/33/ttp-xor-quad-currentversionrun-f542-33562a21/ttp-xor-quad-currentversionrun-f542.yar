rule TTP_XOR_QUAD_CurrentVersionRun_f542 {
  strings:
    $key_f542 = { a6 2d [2] 82 23 [2] a9 0f [2] 87 2d [2] 93 36 [2] 9c 2c [2] 82 31 [2] 80 30 [2] 9b 36 [2] 87 31 [2] 9b 1e }

  condition:
    any of them
}