rule TTP_XOR_QUAD_CurrentVersionRun_bf81 {
  strings:
    $key_bf81 = { ec ee [2] c8 e0 [2] e3 cc [2] cd ee [2] d9 f5 [2] d6 ef [2] c8 f2 [2] ca f3 [2] d1 f5 [2] cd f2 [2] d1 dd }

  condition:
    any of them
}