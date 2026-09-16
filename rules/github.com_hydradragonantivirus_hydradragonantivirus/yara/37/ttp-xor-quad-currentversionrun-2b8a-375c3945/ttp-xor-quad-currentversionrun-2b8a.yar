rule TTP_XOR_QUAD_CurrentVersionRun_2b8a {
  strings:
    $key_2b8a = { 78 e5 [2] 5c eb [2] 77 c7 [2] 59 e5 [2] 4d fe [2] 42 e4 [2] 5c f9 [2] 5e f8 [2] 45 fe [2] 59 f9 [2] 45 d6 }

  condition:
    any of them
}