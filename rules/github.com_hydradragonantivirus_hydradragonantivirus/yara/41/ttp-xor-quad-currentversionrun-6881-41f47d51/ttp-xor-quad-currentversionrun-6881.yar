rule TTP_XOR_QUAD_CurrentVersionRun_6881 {
  strings:
    $key_6881 = { 3b ee [2] 1f e0 [2] 34 cc [2] 1a ee [2] 0e f5 [2] 01 ef [2] 1f f2 [2] 1d f3 [2] 06 f5 [2] 1a f2 [2] 06 dd }

  condition:
    any of them
}