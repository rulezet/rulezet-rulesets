rule TTP_XOR_QUAD_CurrentVersionRun_bf9e {
  strings:
    $key_bf9e = { ec f1 [2] c8 ff [2] e3 d3 [2] cd f1 [2] d9 ea [2] d6 f0 [2] c8 ed [2] ca ec [2] d1 ea [2] cd ed [2] d1 c2 }

  condition:
    any of them
}