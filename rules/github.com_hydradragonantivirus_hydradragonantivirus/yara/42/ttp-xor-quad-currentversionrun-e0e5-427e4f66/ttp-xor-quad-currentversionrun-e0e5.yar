rule TTP_XOR_QUAD_CurrentVersionRun_e0e5 {
  strings:
    $key_e0e5 = { b3 8a [2] 97 84 [2] bc a8 [2] 92 8a [2] 86 91 [2] 89 8b [2] 97 96 [2] 95 97 [2] 8e 91 [2] 92 96 [2] 8e b9 }

  condition:
    any of them
}