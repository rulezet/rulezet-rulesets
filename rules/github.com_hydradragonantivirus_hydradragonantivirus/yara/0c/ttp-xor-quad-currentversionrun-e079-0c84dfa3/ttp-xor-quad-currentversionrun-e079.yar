rule TTP_XOR_QUAD_CurrentVersionRun_e079 {
  strings:
    $key_e079 = { b3 16 [2] 97 18 [2] bc 34 [2] 92 16 [2] 86 0d [2] 89 17 [2] 97 0a [2] 95 0b [2] 8e 0d [2] 92 0a [2] 8e 25 }

  condition:
    any of them
}