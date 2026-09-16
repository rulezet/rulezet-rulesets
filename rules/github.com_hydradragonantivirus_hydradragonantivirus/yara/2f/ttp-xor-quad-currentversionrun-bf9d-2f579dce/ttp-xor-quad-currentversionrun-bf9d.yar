rule TTP_XOR_QUAD_CurrentVersionRun_bf9d {
  strings:
    $key_bf9d = { ec f2 [2] c8 fc [2] e3 d0 [2] cd f2 [2] d9 e9 [2] d6 f3 [2] c8 ee [2] ca ef [2] d1 e9 [2] cd ee [2] d1 c1 }

  condition:
    any of them
}