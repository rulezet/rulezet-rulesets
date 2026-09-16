rule TTP_XOR_QUAD_CurrentVersionRun_7a8a {
  strings:
    $key_7a8a = { 29 e5 [2] 0d eb [2] 26 c7 [2] 08 e5 [2] 1c fe [2] 13 e4 [2] 0d f9 [2] 0f f8 [2] 14 fe [2] 08 f9 [2] 14 d6 }

  condition:
    any of them
}