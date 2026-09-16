rule TTP_XOR_QUAD_CurrentVersionRun_4d81 {
  strings:
    $key_4d81 = { 1e ee [2] 3a e0 [2] 11 cc [2] 3f ee [2] 2b f5 [2] 24 ef [2] 3a f2 [2] 38 f3 [2] 23 f5 [2] 3f f2 [2] 23 dd }

  condition:
    any of them
}