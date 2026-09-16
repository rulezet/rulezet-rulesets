rule TTP_XOR_QUAD_CurrentVersionRun_e085 {
  strings:
    $key_e085 = { b3 ea [2] 97 e4 [2] bc c8 [2] 92 ea [2] 86 f1 [2] 89 eb [2] 97 f6 [2] 95 f7 [2] 8e f1 [2] 92 f6 [2] 8e d9 }

  condition:
    any of them
}