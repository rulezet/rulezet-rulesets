rule TTP_XOR_QUAD_CurrentVersionRun_3981 {
  strings:
    $key_3981 = { 6a ee [2] 4e e0 [2] 65 cc [2] 4b ee [2] 5f f5 [2] 50 ef [2] 4e f2 [2] 4c f3 [2] 57 f5 [2] 4b f2 [2] 57 dd }

  condition:
    any of them
}