rule TTP_XOR_QUAD_CurrentVersionRun_5981 {
  strings:
    $key_5981 = { 0a ee [2] 2e e0 [2] 05 cc [2] 2b ee [2] 3f f5 [2] 30 ef [2] 2e f2 [2] 2c f3 [2] 37 f5 [2] 2b f2 [2] 37 dd }

  condition:
    any of them
}