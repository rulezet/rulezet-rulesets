rule TTP_XOR_QUAD_CurrentVersionRun_139d {
  strings:
    $key_139d = { 40 f2 [2] 64 fc [2] 4f d0 [2] 61 f2 [2] 75 e9 [2] 7a f3 [2] 64 ee [2] 66 ef [2] 7d e9 [2] 61 ee [2] 7d c1 }

  condition:
    any of them
}