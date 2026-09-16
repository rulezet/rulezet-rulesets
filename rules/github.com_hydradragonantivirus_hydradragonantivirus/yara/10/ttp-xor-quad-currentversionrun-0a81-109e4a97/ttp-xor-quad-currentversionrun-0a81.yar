rule TTP_XOR_QUAD_CurrentVersionRun_0a81 {
  strings:
    $key_0a81 = { 59 ee [2] 7d e0 [2] 56 cc [2] 78 ee [2] 6c f5 [2] 63 ef [2] 7d f2 [2] 7f f3 [2] 64 f5 [2] 78 f2 [2] 64 dd }

  condition:
    any of them
}