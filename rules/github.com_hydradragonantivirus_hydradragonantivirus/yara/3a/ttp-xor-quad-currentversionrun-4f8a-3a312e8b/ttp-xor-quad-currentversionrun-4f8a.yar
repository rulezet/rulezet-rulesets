rule TTP_XOR_QUAD_CurrentVersionRun_4f8a {
  strings:
    $key_4f8a = { 1c e5 [2] 38 eb [2] 13 c7 [2] 3d e5 [2] 29 fe [2] 26 e4 [2] 38 f9 [2] 3a f8 [2] 21 fe [2] 3d f9 [2] 21 d6 }

  condition:
    any of them
}