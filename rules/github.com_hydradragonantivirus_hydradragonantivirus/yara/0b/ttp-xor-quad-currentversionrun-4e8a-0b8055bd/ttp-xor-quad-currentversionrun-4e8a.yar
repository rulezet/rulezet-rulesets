rule TTP_XOR_QUAD_CurrentVersionRun_4e8a {
  strings:
    $key_4e8a = { 1d e5 [2] 39 eb [2] 12 c7 [2] 3c e5 [2] 28 fe [2] 27 e4 [2] 39 f9 [2] 3b f8 [2] 20 fe [2] 3c f9 [2] 20 d6 }

  condition:
    any of them
}