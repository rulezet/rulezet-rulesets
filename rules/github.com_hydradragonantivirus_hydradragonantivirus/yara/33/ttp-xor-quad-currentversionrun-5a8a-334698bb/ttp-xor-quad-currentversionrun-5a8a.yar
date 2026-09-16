rule TTP_XOR_QUAD_CurrentVersionRun_5a8a {
  strings:
    $key_5a8a = { 09 e5 [2] 2d eb [2] 06 c7 [2] 28 e5 [2] 3c fe [2] 33 e4 [2] 2d f9 [2] 2f f8 [2] 34 fe [2] 28 f9 [2] 34 d6 }

  condition:
    any of them
}