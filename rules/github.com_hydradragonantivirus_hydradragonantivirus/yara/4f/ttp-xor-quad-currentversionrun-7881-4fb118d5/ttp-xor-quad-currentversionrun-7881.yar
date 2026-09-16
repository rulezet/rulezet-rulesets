rule TTP_XOR_QUAD_CurrentVersionRun_7881 {
  strings:
    $key_7881 = { 2b ee [2] 0f e0 [2] 24 cc [2] 0a ee [2] 1e f5 [2] 11 ef [2] 0f f2 [2] 0d f3 [2] 16 f5 [2] 0a f2 [2] 16 dd }

  condition:
    any of them
}