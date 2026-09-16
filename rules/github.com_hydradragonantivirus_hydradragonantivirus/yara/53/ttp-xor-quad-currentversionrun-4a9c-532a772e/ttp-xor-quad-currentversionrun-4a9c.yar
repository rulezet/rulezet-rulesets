rule TTP_XOR_QUAD_CurrentVersionRun_4a9c {
  strings:
    $key_4a9c = { 19 f3 [2] 3d fd [2] 16 d1 [2] 38 f3 [2] 2c e8 [2] 23 f2 [2] 3d ef [2] 3f ee [2] 24 e8 [2] 38 ef [2] 24 c0 }

  condition:
    any of them
}