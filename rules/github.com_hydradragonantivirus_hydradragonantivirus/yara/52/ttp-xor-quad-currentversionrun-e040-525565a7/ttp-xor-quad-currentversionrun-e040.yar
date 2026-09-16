rule TTP_XOR_QUAD_CurrentVersionRun_e040 {
  strings:
    $key_e040 = { b3 2f [2] 97 21 [2] bc 0d [2] 92 2f [2] 86 34 [2] 89 2e [2] 97 33 [2] 95 32 [2] 8e 34 [2] 92 33 [2] 8e 1c }

  condition:
    any of them
}