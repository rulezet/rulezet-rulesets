rule TTP_XOR_QUAD_CurrentVersionRun_1543 {
  strings:
    $key_1543 = { 46 2c [2] 62 22 [2] 49 0e [2] 67 2c [2] 73 37 [2] 7c 2d [2] 62 30 [2] 60 31 [2] 7b 37 [2] 67 30 [2] 7b 1f }

  condition:
    any of them
}