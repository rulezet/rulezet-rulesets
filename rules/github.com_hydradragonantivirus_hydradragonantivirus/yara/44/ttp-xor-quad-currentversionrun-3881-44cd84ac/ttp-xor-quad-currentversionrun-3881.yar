rule TTP_XOR_QUAD_CurrentVersionRun_3881 {
  strings:
    $key_3881 = { 6b ee [2] 4f e0 [2] 64 cc [2] 4a ee [2] 5e f5 [2] 51 ef [2] 4f f2 [2] 4d f3 [2] 56 f5 [2] 4a f2 [2] 56 dd }

  condition:
    any of them
}