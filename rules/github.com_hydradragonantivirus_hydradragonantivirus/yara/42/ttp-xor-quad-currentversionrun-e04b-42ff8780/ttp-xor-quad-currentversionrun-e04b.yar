rule TTP_XOR_QUAD_CurrentVersionRun_e04b {
  strings:
    $key_e04b = { b3 24 [2] 97 2a [2] bc 06 [2] 92 24 [2] 86 3f [2] 89 25 [2] 97 38 [2] 95 39 [2] 8e 3f [2] 92 38 [2] 8e 17 }

  condition:
    any of them
}