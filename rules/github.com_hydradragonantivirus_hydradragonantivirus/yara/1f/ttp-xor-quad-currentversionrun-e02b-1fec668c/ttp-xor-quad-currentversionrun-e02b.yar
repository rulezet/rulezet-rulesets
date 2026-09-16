rule TTP_XOR_QUAD_CurrentVersionRun_e02b {
  strings:
    $key_e02b = { b3 44 [2] 97 4a [2] bc 66 [2] 92 44 [2] 86 5f [2] 89 45 [2] 97 58 [2] 95 59 [2] 8e 5f [2] 92 58 [2] 8e 77 }

  condition:
    any of them
}