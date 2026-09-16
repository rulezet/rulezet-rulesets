rule TTP_XOR_QUAD_CurrentVersionRun_419d {
  strings:
    $key_419d = { 12 f2 [2] 36 fc [2] 1d d0 [2] 33 f2 [2] 27 e9 [2] 28 f3 [2] 36 ee [2] 34 ef [2] 2f e9 [2] 33 ee [2] 2f c1 }

  condition:
    any of them
}