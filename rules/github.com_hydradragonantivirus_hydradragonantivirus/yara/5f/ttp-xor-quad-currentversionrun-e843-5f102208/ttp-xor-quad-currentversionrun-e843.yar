rule TTP_XOR_QUAD_CurrentVersionRun_e843 {
  strings:
    $key_e843 = { bb 2c [2] 9f 22 [2] b4 0e [2] 9a 2c [2] 8e 37 [2] 81 2d [2] 9f 30 [2] 9d 31 [2] 86 37 [2] 9a 30 [2] 86 1f }

  condition:
    any of them
}