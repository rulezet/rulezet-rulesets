rule TTP_XOR_QUAD_CurrentVersionRun_e02c {
  strings:
    $key_e02c = { b3 43 [2] 97 4d [2] bc 61 [2] 92 43 [2] 86 58 [2] 89 42 [2] 97 5f [2] 95 5e [2] 8e 58 [2] 92 5f [2] 8e 70 }

  condition:
    any of them
}