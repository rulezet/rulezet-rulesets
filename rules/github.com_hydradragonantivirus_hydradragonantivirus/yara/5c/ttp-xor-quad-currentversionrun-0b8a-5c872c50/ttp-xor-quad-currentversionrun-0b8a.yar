rule TTP_XOR_QUAD_CurrentVersionRun_0b8a {
  strings:
    $key_0b8a = { 58 e5 [2] 7c eb [2] 57 c7 [2] 79 e5 [2] 6d fe [2] 62 e4 [2] 7c f9 [2] 7e f8 [2] 65 fe [2] 79 f9 [2] 65 d6 }

  condition:
    any of them
}