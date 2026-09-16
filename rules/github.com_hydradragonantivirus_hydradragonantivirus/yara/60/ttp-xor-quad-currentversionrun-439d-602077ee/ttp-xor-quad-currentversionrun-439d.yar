rule TTP_XOR_QUAD_CurrentVersionRun_439d {
  strings:
    $key_439d = { 10 f2 [2] 34 fc [2] 1f d0 [2] 31 f2 [2] 25 e9 [2] 2a f3 [2] 34 ee [2] 36 ef [2] 2d e9 [2] 31 ee [2] 2d c1 }

  condition:
    any of them
}