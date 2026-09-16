rule TTP_XOR_QUAD_CurrentVersionRun_e981 {
  strings:
    $key_e981 = { ba ee [2] 9e e0 [2] b5 cc [2] 9b ee [2] 8f f5 [2] 80 ef [2] 9e f2 [2] 9c f3 [2] 87 f5 [2] 9b f2 [2] 87 dd }

  condition:
    any of them
}