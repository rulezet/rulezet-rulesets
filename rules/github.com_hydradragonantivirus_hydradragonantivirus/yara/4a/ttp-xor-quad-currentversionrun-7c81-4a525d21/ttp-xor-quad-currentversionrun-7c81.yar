rule TTP_XOR_QUAD_CurrentVersionRun_7c81 {
  strings:
    $key_7c81 = { 2f ee [2] 0b e0 [2] 20 cc [2] 0e ee [2] 1a f5 [2] 15 ef [2] 0b f2 [2] 09 f3 [2] 12 f5 [2] 0e f2 [2] 12 dd }

  condition:
    any of them
}