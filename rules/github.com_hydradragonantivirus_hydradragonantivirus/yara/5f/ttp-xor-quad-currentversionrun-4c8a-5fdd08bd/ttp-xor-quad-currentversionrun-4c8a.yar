rule TTP_XOR_QUAD_CurrentVersionRun_4c8a {
  strings:
    $key_4c8a = { 1f e5 [2] 3b eb [2] 10 c7 [2] 3e e5 [2] 2a fe [2] 25 e4 [2] 3b f9 [2] 39 f8 [2] 22 fe [2] 3e f9 [2] 22 d6 }

  condition:
    any of them
}