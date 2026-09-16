rule TTP_XOR_QUAD_CurrentVersionRun_0b42 {
  strings:
    $key_0b42 = { 58 2d [2] 7c 23 [2] 57 0f [2] 79 2d [2] 6d 36 [2] 62 2c [2] 7c 31 [2] 7e 30 [2] 65 36 [2] 79 31 [2] 65 1e }

  condition:
    any of them
}