rule TTP_XOR_QUAD_CurrentVersionRun_7b8a {
  strings:
    $key_7b8a = { 28 e5 [2] 0c eb [2] 27 c7 [2] 09 e5 [2] 1d fe [2] 12 e4 [2] 0c f9 [2] 0e f8 [2] 15 fe [2] 09 f9 [2] 15 d6 }

  condition:
    any of them
}