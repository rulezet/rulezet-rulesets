rule TTP_XOR_QUAD_CurrentVersionRun_bf9c {
  strings:
    $key_bf9c = { ec f3 [2] c8 fd [2] e3 d1 [2] cd f3 [2] d9 e8 [2] d6 f2 [2] c8 ef [2] ca ee [2] d1 e8 [2] cd ef [2] d1 c0 }

  condition:
    any of them
}