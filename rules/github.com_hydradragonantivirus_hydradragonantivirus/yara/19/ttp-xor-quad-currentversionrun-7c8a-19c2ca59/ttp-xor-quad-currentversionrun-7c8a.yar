rule TTP_XOR_QUAD_CurrentVersionRun_7c8a {
  strings:
    $key_7c8a = { 2f e5 [2] 0b eb [2] 20 c7 [2] 0e e5 [2] 1a fe [2] 15 e4 [2] 0b f9 [2] 09 f8 [2] 12 fe [2] 0e f9 [2] 12 d6 }

  condition:
    any of them
}