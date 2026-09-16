rule TTP_XOR_QUAD_CurrentVersionRun_e070 {
  strings:
    $key_e070 = { b3 1f [2] 97 11 [2] bc 3d [2] 92 1f [2] 86 04 [2] 89 1e [2] 97 03 [2] 95 02 [2] 8e 04 [2] 92 03 [2] 8e 2c }

  condition:
    any of them
}