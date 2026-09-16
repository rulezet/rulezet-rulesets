rule TTP_XOR_QUAD_CurrentVersionRun_408a {
  strings:
    $key_408a = { 13 e5 [2] 37 eb [2] 1c c7 [2] 32 e5 [2] 26 fe [2] 29 e4 [2] 37 f9 [2] 35 f8 [2] 2e fe [2] 32 f9 [2] 2e d6 }

  condition:
    any of them
}