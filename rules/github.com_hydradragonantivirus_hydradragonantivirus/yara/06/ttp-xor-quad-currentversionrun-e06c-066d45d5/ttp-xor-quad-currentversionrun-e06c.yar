rule TTP_XOR_QUAD_CurrentVersionRun_e06c {
  strings:
    $key_e06c = { b3 03 [2] 97 0d [2] bc 21 [2] 92 03 [2] 86 18 [2] 89 02 [2] 97 1f [2] 95 1e [2] 8e 18 [2] 92 1f [2] 8e 30 }

  condition:
    any of them
}