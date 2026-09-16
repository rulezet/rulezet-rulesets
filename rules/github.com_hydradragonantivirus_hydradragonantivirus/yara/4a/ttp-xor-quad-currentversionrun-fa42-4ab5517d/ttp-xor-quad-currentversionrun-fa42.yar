rule TTP_XOR_QUAD_CurrentVersionRun_fa42 {
  strings:
    $key_fa42 = { a9 2d [2] 8d 23 [2] a6 0f [2] 88 2d [2] 9c 36 [2] 93 2c [2] 8d 31 [2] 8f 30 [2] 94 36 [2] 88 31 [2] 94 1e }

  condition:
    any of them
}