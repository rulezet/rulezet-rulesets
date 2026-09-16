rule TTP_XOR_QUAD_CurrentVersionRun_3d9d {
  strings:
    $key_3d9d = { 6e f2 [2] 4a fc [2] 61 d0 [2] 4f f2 [2] 5b e9 [2] 54 f3 [2] 4a ee [2] 48 ef [2] 53 e9 [2] 4f ee [2] 53 c1 }

  condition:
    any of them
}