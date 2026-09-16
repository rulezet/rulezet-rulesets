rule TTP_XOR_QUAD_CurrentVersionRun_b8ae {
  strings:
    $key_b8ae = { eb c1 [2] cf cf [2] e4 e3 [2] ca c1 [2] de da [2] d1 c0 [2] cf dd [2] cd dc [2] d6 da [2] ca dd [2] d6 f2 }

  condition:
    any of them
}