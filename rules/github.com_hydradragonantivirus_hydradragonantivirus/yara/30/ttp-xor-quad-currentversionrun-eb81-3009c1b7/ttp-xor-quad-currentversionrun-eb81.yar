rule TTP_XOR_QUAD_CurrentVersionRun_eb81 {
  strings:
    $key_eb81 = { b8 ee [2] 9c e0 [2] b7 cc [2] 99 ee [2] 8d f5 [2] 82 ef [2] 9c f2 [2] 9e f3 [2] 85 f5 [2] 99 f2 [2] 85 dd }

  condition:
    any of them
}