rule TTP_XOR_QUAD_CurrentVersionRun_e004 {
  strings:
    $key_e004 = { b3 6b [2] 97 65 [2] bc 49 [2] 92 6b [2] 86 70 [2] 89 6a [2] 97 77 [2] 95 76 [2] 8e 70 [2] 92 77 [2] 8e 58 }

  condition:
    any of them
}