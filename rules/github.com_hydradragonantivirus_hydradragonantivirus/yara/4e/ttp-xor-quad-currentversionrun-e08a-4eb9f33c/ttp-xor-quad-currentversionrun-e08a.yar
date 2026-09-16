rule TTP_XOR_QUAD_CurrentVersionRun_e08a {
  strings:
    $key_e08a = { b3 e5 [2] 97 eb [2] bc c7 [2] 92 e5 [2] 86 fe [2] 89 e4 [2] 97 f9 [2] 95 f8 [2] 8e fe [2] 92 f9 [2] 8e d6 }

  condition:
    any of them
}