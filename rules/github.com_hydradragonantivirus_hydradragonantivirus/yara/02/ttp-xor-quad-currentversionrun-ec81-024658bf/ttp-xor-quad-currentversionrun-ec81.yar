rule TTP_XOR_QUAD_CurrentVersionRun_ec81 {
  strings:
    $key_ec81 = { bf ee [2] 9b e0 [2] b0 cc [2] 9e ee [2] 8a f5 [2] 85 ef [2] 9b f2 [2] 99 f3 [2] 82 f5 [2] 9e f2 [2] 82 dd }

  condition:
    any of them
}