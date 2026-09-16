rule TTP_XOR_QUAD_CurrentVersionRun_608a {
  strings:
    $key_608a = { 33 e5 [2] 17 eb [2] 3c c7 [2] 12 e5 [2] 06 fe [2] 09 e4 [2] 17 f9 [2] 15 f8 [2] 0e fe [2] 12 f9 [2] 0e d6 }

  condition:
    any of them
}