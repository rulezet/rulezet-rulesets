rule TTP_XOR_QUAD_CurrentVersionRun_0981 {
  strings:
    $key_0981 = { 5a ee [2] 7e e0 [2] 55 cc [2] 7b ee [2] 6f f5 [2] 60 ef [2] 7e f2 [2] 7c f3 [2] 67 f5 [2] 7b f2 [2] 67 dd }

  condition:
    any of them
}