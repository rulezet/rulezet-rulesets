rule TTP_XOR_QUAD_CurrentVersionRun_7e43 {
  strings:
    $key_7e43 = { 2d 2c [2] 09 22 [2] 22 0e [2] 0c 2c [2] 18 37 [2] 17 2d [2] 09 30 [2] 0b 31 [2] 10 37 [2] 0c 30 [2] 10 1f }

  condition:
    any of them
}