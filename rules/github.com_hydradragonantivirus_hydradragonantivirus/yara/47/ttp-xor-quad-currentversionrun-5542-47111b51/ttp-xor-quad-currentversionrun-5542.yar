rule TTP_XOR_QUAD_CurrentVersionRun_5542 {
  strings:
    $key_5542 = { 06 2d [2] 22 23 [2] 09 0f [2] 27 2d [2] 33 36 [2] 3c 2c [2] 22 31 [2] 20 30 [2] 3b 36 [2] 27 31 [2] 3b 1e }

  condition:
    any of them
}