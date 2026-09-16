rule TTP_XOR_QUAD_CurrentVersionRun_4881 {
  strings:
    $key_4881 = { 1b ee [2] 3f e0 [2] 14 cc [2] 3a ee [2] 2e f5 [2] 21 ef [2] 3f f2 [2] 3d f3 [2] 26 f5 [2] 3a f2 [2] 26 dd }

  condition:
    any of them
}