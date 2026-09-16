rule TTP_XOR_QUAD_CurrentVersionRun_4981 {
  strings:
    $key_4981 = { 1a ee [2] 3e e0 [2] 15 cc [2] 3b ee [2] 2f f5 [2] 20 ef [2] 3e f2 [2] 3c f3 [2] 27 f5 [2] 3b f2 [2] 27 dd }

  condition:
    any of them
}