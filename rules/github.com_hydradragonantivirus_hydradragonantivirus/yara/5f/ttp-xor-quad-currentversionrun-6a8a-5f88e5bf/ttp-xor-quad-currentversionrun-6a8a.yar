rule TTP_XOR_QUAD_CurrentVersionRun_6a8a {
  strings:
    $key_6a8a = { 39 e5 [2] 1d eb [2] 36 c7 [2] 18 e5 [2] 0c fe [2] 03 e4 [2] 1d f9 [2] 1f f8 [2] 04 fe [2] 18 f9 [2] 04 d6 }

  condition:
    any of them
}