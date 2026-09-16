rule TTP_XOR_QUAD_CurrentVersionRun_e05c {
  strings:
    $key_e05c = { b3 33 [2] 97 3d [2] bc 11 [2] 92 33 [2] 86 28 [2] 89 32 [2] 97 2f [2] 95 2e [2] 8e 28 [2] 92 2f [2] 8e 00 }

  condition:
    any of them
}