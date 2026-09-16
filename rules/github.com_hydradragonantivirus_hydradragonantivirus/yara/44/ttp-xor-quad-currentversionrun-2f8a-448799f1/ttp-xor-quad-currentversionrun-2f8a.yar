rule TTP_XOR_QUAD_CurrentVersionRun_2f8a {
  strings:
    $key_2f8a = { 7c e5 [2] 58 eb [2] 73 c7 [2] 5d e5 [2] 49 fe [2] 46 e4 [2] 58 f9 [2] 5a f8 [2] 41 fe [2] 5d f9 [2] 41 d6 }

  condition:
    any of them
}