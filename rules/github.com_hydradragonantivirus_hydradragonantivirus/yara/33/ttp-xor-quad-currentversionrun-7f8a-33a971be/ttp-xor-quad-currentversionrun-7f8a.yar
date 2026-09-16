rule TTP_XOR_QUAD_CurrentVersionRun_7f8a {
  strings:
    $key_7f8a = { 2c e5 [2] 08 eb [2] 23 c7 [2] 0d e5 [2] 19 fe [2] 16 e4 [2] 08 f9 [2] 0a f8 [2] 11 fe [2] 0d f9 [2] 11 d6 }

  condition:
    any of them
}