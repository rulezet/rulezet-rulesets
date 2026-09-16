rule TTP_XOR_QUAD_CurrentVersionRun_249d {
  strings:
    $key_249d = { 77 f2 [2] 53 fc [2] 78 d0 [2] 56 f2 [2] 42 e9 [2] 4d f3 [2] 53 ee [2] 51 ef [2] 4a e9 [2] 56 ee [2] 4a c1 }

  condition:
    any of them
}