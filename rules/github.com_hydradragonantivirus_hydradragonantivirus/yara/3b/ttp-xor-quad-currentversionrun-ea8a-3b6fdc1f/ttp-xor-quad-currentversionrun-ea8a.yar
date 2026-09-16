rule TTP_XOR_QUAD_CurrentVersionRun_ea8a {
  strings:
    $key_ea8a = { b9 e5 [2] 9d eb [2] b6 c7 [2] 98 e5 [2] 8c fe [2] 83 e4 [2] 9d f9 [2] 9f f8 [2] 84 fe [2] 98 f9 [2] 84 d6 }

  condition:
    any of them
}