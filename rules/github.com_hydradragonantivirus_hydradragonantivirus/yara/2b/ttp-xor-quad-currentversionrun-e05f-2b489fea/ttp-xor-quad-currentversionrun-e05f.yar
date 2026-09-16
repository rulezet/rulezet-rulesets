rule TTP_XOR_QUAD_CurrentVersionRun_e05f {
  strings:
    $key_e05f = { b3 30 [2] 97 3e [2] bc 12 [2] 92 30 [2] 86 2b [2] 89 31 [2] 97 2c [2] 95 2d [2] 8e 2b [2] 92 2c [2] 8e 03 }

  condition:
    any of them
}