rule TTP_XOR_QUAD_CurrentVersionRun_e0c6 {
  strings:
    $key_e0c6 = { b3 a9 [2] 97 a7 [2] bc 8b [2] 92 a9 [2] 86 b2 [2] 89 a8 [2] 97 b5 [2] 95 b4 [2] 8e b2 [2] 92 b5 [2] 8e 9a }

  condition:
    any of them
}