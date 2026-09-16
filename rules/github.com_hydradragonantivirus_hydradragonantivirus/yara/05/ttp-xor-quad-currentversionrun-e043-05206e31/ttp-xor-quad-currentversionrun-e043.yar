rule TTP_XOR_QUAD_CurrentVersionRun_e043 {
  strings:
    $key_e043 = { b3 2c [2] 97 22 [2] bc 0e [2] 92 2c [2] 86 37 [2] 89 2d [2] 97 30 [2] 95 31 [2] 8e 37 [2] 92 30 [2] 8e 1f }

  condition:
    any of them
}