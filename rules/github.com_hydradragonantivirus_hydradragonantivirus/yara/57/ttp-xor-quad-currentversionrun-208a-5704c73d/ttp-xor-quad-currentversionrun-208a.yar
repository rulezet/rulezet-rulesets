rule TTP_XOR_QUAD_CurrentVersionRun_208a {
  strings:
    $key_208a = { 73 e5 [2] 57 eb [2] 7c c7 [2] 52 e5 [2] 46 fe [2] 49 e4 [2] 57 f9 [2] 55 f8 [2] 4e fe [2] 52 f9 [2] 4e d6 }

  condition:
    any of them
}