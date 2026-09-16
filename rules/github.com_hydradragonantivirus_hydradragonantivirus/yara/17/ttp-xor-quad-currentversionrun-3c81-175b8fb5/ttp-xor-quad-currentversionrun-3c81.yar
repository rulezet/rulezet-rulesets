rule TTP_XOR_QUAD_CurrentVersionRun_3c81 {
  strings:
    $key_3c81 = { 6f ee [2] 4b e0 [2] 60 cc [2] 4e ee [2] 5a f5 [2] 55 ef [2] 4b f2 [2] 49 f3 [2] 52 f5 [2] 4e f2 [2] 52 dd }

  condition:
    any of them
}