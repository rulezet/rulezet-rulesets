rule TTP_XOR_QUAD_CurrentVersionRun_e0e4 {
  strings:
    $key_e0e4 = { b3 8b [2] 97 85 [2] bc a9 [2] 92 8b [2] 86 90 [2] 89 8a [2] 97 97 [2] 95 96 [2] 8e 90 [2] 92 97 [2] 8e b8 }

  condition:
    any of them
}