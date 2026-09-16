rule TTP_XOR_QUAD_CurrentVersionRun_fb8a {
  strings:
    $key_fb8a = { a8 e5 [2] 8c eb [2] a7 c7 [2] 89 e5 [2] 9d fe [2] 92 e4 [2] 8c f9 [2] 8e f8 [2] 95 fe [2] 89 f9 [2] 95 d6 }

  condition:
    any of them
}