rule TTP_XOR_QUAD_CurrentVersionRun_3b8a {
  strings:
    $key_3b8a = { 68 e5 [2] 4c eb [2] 67 c7 [2] 49 e5 [2] 5d fe [2] 52 e4 [2] 4c f9 [2] 4e f8 [2] 55 fe [2] 49 f9 [2] 55 d6 }

  condition:
    any of them
}