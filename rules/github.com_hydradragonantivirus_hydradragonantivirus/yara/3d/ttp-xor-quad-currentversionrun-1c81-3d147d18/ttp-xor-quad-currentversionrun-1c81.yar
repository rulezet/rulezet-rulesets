rule TTP_XOR_QUAD_CurrentVersionRun_1c81 {
  strings:
    $key_1c81 = { 4f ee [2] 6b e0 [2] 40 cc [2] 6e ee [2] 7a f5 [2] 75 ef [2] 6b f2 [2] 69 f3 [2] 72 f5 [2] 6e f2 [2] 72 dd }

  condition:
    any of them
}