rule TTP_XOR_QUAD_CurrentVersionRun_1c42 {
  strings:
    $key_1c42 = { 4f 2d [2] 6b 23 [2] 40 0f [2] 6e 2d [2] 7a 36 [2] 75 2c [2] 6b 31 [2] 69 30 [2] 72 36 [2] 6e 31 [2] 72 1e }

  condition:
    any of them
}