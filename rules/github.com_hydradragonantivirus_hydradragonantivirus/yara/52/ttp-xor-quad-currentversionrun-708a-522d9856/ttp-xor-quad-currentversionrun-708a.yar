rule TTP_XOR_QUAD_CurrentVersionRun_708a {
  strings:
    $key_708a = { 23 e5 [2] 07 eb [2] 2c c7 [2] 02 e5 [2] 16 fe [2] 19 e4 [2] 07 f9 [2] 05 f8 [2] 1e fe [2] 02 f9 [2] 1e d6 }

  condition:
    any of them
}