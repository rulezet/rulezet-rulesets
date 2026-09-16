rule TTP_XOR_QUAD_CurrentVersionRun_2442 {
  strings:
    $key_2442 = { 77 2d [2] 53 23 [2] 78 0f [2] 56 2d [2] 42 36 [2] 4d 2c [2] 53 31 [2] 51 30 [2] 4a 36 [2] 56 31 [2] 4a 1e }

  condition:
    any of them
}