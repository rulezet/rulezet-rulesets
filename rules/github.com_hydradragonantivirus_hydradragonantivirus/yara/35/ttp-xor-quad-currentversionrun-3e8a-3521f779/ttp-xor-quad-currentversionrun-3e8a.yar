rule TTP_XOR_QUAD_CurrentVersionRun_3e8a {
  strings:
    $key_3e8a = { 6d e5 [2] 49 eb [2] 62 c7 [2] 4c e5 [2] 58 fe [2] 57 e4 [2] 49 f9 [2] 4b f8 [2] 50 fe [2] 4c f9 [2] 50 d6 }

  condition:
    any of them
}