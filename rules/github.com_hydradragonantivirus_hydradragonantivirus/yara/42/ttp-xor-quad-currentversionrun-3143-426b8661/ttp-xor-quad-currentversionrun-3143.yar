rule TTP_XOR_QUAD_CurrentVersionRun_3143 {
  strings:
    $key_3143 = { 62 2c [2] 46 22 [2] 6d 0e [2] 43 2c [2] 57 37 [2] 58 2d [2] 46 30 [2] 44 31 [2] 5f 37 [2] 43 30 [2] 5f 1f }

  condition:
    any of them
}