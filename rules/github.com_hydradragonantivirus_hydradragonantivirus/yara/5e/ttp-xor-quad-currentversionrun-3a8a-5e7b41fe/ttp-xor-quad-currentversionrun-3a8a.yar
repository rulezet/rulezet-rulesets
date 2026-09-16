rule TTP_XOR_QUAD_CurrentVersionRun_3a8a {
  strings:
    $key_3a8a = { 69 e5 [2] 4d eb [2] 66 c7 [2] 48 e5 [2] 5c fe [2] 53 e4 [2] 4d f9 [2] 4f f8 [2] 54 fe [2] 48 f9 [2] 54 d6 }

  condition:
    any of them
}