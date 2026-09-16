rule TTP_XOR_QUAD_CurrentVersionRun_2d42 {
  strings:
    $key_2d42 = { 7e 2d [2] 5a 23 [2] 71 0f [2] 5f 2d [2] 4b 36 [2] 44 2c [2] 5a 31 [2] 58 30 [2] 43 36 [2] 5f 31 [2] 43 1e }

  condition:
    any of them
}