rule TTP_XOR_QUAD_CurrentVersionRun_2542 {
  strings:
    $key_2542 = { 76 2d [2] 52 23 [2] 79 0f [2] 57 2d [2] 43 36 [2] 4c 2c [2] 52 31 [2] 50 30 [2] 4b 36 [2] 57 31 [2] 4b 1e }

  condition:
    any of them
}