rule TTP_XOR_QUAD_CurrentVersionRun_e05d {
  strings:
    $key_e05d = { b3 32 [2] 97 3c [2] bc 10 [2] 92 32 [2] 86 29 [2] 89 33 [2] 97 2e [2] 95 2f [2] 8e 29 [2] 92 2e [2] 8e 01 }

  condition:
    any of them
}