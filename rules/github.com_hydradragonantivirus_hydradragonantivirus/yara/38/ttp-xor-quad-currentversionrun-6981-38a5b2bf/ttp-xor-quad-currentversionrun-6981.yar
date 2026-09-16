rule TTP_XOR_QUAD_CurrentVersionRun_6981 {
  strings:
    $key_6981 = { 3a ee [2] 1e e0 [2] 35 cc [2] 1b ee [2] 0f f5 [2] 00 ef [2] 1e f2 [2] 1c f3 [2] 07 f5 [2] 1b f2 [2] 07 dd }

  condition:
    any of them
}