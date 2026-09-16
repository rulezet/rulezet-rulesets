rule TTP_XOR_QUAD_CurrentVersionRun_f843 {
  strings:
    $key_f843 = { ab 2c [2] 8f 22 [2] a4 0e [2] 8a 2c [2] 9e 37 [2] 91 2d [2] 8f 30 [2] 8d 31 [2] 96 37 [2] 8a 30 [2] 96 1f }

  condition:
    any of them
}