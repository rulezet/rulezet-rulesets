rule TTP_XOR_QUAD_CurrentVersionRun_f143 {
  strings:
    $key_f143 = { a2 2c [2] 86 22 [2] ad 0e [2] 83 2c [2] 97 37 [2] 98 2d [2] 86 30 [2] 84 31 [2] 9f 37 [2] 83 30 [2] 9f 1f }

  condition:
    any of them
}