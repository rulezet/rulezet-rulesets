rule TTP_XOR_QUAD_CurrentVersionRun_e041 {
  strings:
    $key_e041 = { b3 2e [2] 97 20 [2] bc 0c [2] 92 2e [2] 86 35 [2] 89 2f [2] 97 32 [2] 95 33 [2] 8e 35 [2] 92 32 [2] 8e 1d }

  condition:
    any of them
}