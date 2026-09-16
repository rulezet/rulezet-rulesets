rule TTP_XOR_QUAD_CurrentVersionRun_2a9d {
  strings:
    $key_2a9d = { 79 f2 [2] 5d fc [2] 76 d0 [2] 58 f2 [2] 4c e9 [2] 43 f3 [2] 5d ee [2] 5f ef [2] 44 e9 [2] 58 ee [2] 44 c1 }

  condition:
    any of them
}