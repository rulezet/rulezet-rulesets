rule TTP_XOR_QUAD_CurrentVersionRun_5f8a {
  strings:
    $key_5f8a = { 0c e5 [2] 28 eb [2] 03 c7 [2] 2d e5 [2] 39 fe [2] 36 e4 [2] 28 f9 [2] 2a f8 [2] 31 fe [2] 2d f9 [2] 31 d6 }

  condition:
    any of them
}