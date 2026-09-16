rule TTP_XOR_QUAD_CurrentVersionRun_749d {
  strings:
    $key_749d = { 27 f2 [2] 03 fc [2] 28 d0 [2] 06 f2 [2] 12 e9 [2] 1d f3 [2] 03 ee [2] 01 ef [2] 1a e9 [2] 06 ee [2] 1a c1 }

  condition:
    any of them
}