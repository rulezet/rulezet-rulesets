rule TTP_XOR_QUAD_CurrentVersionRun_0143 {
  strings:
    $key_0143 = { 52 2c [2] 76 22 [2] 5d 0e [2] 73 2c [2] 67 37 [2] 68 2d [2] 76 30 [2] 74 31 [2] 6f 37 [2] 73 30 [2] 6f 1f }

  condition:
    any of them
}