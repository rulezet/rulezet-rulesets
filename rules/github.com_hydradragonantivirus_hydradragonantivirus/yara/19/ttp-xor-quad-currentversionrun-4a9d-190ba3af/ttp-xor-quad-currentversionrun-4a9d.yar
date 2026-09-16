rule TTP_XOR_QUAD_CurrentVersionRun_4a9d {
  strings:
    $key_4a9d = { 19 f2 [2] 3d fc [2] 16 d0 [2] 38 f2 [2] 2c e9 [2] 23 f3 [2] 3d ee [2] 3f ef [2] 24 e9 [2] 38 ee [2] 24 c1 }

  condition:
    any of them
}