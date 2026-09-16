rule TTP_XOR_QUAD_CurrentVersionRun_279d {
  strings:
    $key_279d = { 74 f2 [2] 50 fc [2] 7b d0 [2] 55 f2 [2] 41 e9 [2] 4e f3 [2] 50 ee [2] 52 ef [2] 49 e9 [2] 55 ee [2] 49 c1 }

  condition:
    any of them
}