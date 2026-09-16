rule TTP_XOR_QUAD_CurrentVersionRun_719d {
  strings:
    $key_719d = { 22 f2 [2] 06 fc [2] 2d d0 [2] 03 f2 [2] 17 e9 [2] 18 f3 [2] 06 ee [2] 04 ef [2] 1f e9 [2] 03 ee [2] 1f c1 }

  condition:
    any of them
}