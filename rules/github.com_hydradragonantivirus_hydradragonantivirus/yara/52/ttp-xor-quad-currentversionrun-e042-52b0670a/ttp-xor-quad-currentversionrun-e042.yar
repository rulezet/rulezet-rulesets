rule TTP_XOR_QUAD_CurrentVersionRun_e042 {
  strings:
    $key_e042 = { b3 2d [2] 97 23 [2] bc 0f [2] 92 2d [2] 86 36 [2] 89 2c [2] 97 31 [2] 95 30 [2] 8e 36 [2] 92 31 [2] 8e 1e }

  condition:
    any of them
}