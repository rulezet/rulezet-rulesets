rule TTP_XOR_QUAD_CurrentVersionRun_249a {
  strings:
    $key_249a = { 77 f5 [2] 53 fb [2] 78 d7 [2] 56 f5 [2] 42 ee [2] 4d f4 [2] 53 e9 [2] 51 e8 [2] 4a ee [2] 56 e9 [2] 4a c6 }

  condition:
    any of them
}