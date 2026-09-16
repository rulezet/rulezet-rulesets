rule TTP_XOR_QUAD_CurrentVersionRun_0d9d {
  strings:
    $key_0d9d = { 5e f2 [2] 7a fc [2] 51 d0 [2] 7f f2 [2] 6b e9 [2] 64 f3 [2] 7a ee [2] 78 ef [2] 63 e9 [2] 7f ee [2] 63 c1 }

  condition:
    any of them
}