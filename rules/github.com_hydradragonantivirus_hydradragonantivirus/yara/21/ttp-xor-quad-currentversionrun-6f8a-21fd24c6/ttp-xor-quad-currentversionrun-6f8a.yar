rule TTP_XOR_QUAD_CurrentVersionRun_6f8a {
  strings:
    $key_6f8a = { 3c e5 [2] 18 eb [2] 33 c7 [2] 1d e5 [2] 09 fe [2] 06 e4 [2] 18 f9 [2] 1a f8 [2] 01 fe [2] 1d f9 [2] 01 d6 }

  condition:
    any of them
}