rule TTP_XOR_QUAD_CurrentVersionRun_368a {
  strings:
    $key_368a = { 65 e5 [2] 41 eb [2] 6a c7 [2] 44 e5 [2] 50 fe [2] 5f e4 [2] 41 f9 [2] 43 f8 [2] 58 fe [2] 44 f9 [2] 58 d6 }

  condition:
    any of them
}