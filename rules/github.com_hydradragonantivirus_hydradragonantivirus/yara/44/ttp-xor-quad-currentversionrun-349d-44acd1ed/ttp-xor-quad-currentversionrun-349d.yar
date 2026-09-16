rule TTP_XOR_QUAD_CurrentVersionRun_349d {
  strings:
    $key_349d = { 67 f2 [2] 43 fc [2] 68 d0 [2] 46 f2 [2] 52 e9 [2] 5d f3 [2] 43 ee [2] 41 ef [2] 5a e9 [2] 46 ee [2] 5a c1 }

  condition:
    any of them
}