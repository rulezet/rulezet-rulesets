rule TTP_XOR_QUAD_CurrentVersionRun_e02e {
  strings:
    $key_e02e = { b3 41 [2] 97 4f [2] bc 63 [2] 92 41 [2] 86 5a [2] 89 40 [2] 97 5d [2] 95 5c [2] 8e 5a [2] 92 5d [2] 8e 72 }

  condition:
    any of them
}