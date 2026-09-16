rule TTP_XOR_QUAD_CurrentVersionRun_7542 {
  strings:
    $key_7542 = { 26 2d [2] 02 23 [2] 29 0f [2] 07 2d [2] 13 36 [2] 1c 2c [2] 02 31 [2] 00 30 [2] 1b 36 [2] 07 31 [2] 1b 1e }

  condition:
    any of them
}