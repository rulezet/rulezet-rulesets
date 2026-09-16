rule TTP_XOR_QUAD_CurrentVersionRun_fc81 {
  strings:
    $key_fc81 = { af ee [2] 8b e0 [2] a0 cc [2] 8e ee [2] 9a f5 [2] 95 ef [2] 8b f2 [2] 89 f3 [2] 92 f5 [2] 8e f2 [2] 92 dd }

  condition:
    any of them
}