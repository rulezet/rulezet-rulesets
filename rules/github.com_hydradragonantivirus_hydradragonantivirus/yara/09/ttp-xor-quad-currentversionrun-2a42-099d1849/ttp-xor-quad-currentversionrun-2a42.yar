rule TTP_XOR_QUAD_CurrentVersionRun_2a42 {
  strings:
    $key_2a42 = { 79 2d [2] 5d 23 [2] 76 0f [2] 58 2d [2] 4c 36 [2] 43 2c [2] 5d 31 [2] 5f 30 [2] 44 36 [2] 58 31 [2] 44 1e }

  condition:
    any of them
}