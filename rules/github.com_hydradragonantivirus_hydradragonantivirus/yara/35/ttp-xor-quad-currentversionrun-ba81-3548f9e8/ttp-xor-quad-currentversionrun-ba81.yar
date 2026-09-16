rule TTP_XOR_QUAD_CurrentVersionRun_ba81 {
  strings:
    $key_ba81 = { e9 ee [2] cd e0 [2] e6 cc [2] c8 ee [2] dc f5 [2] d3 ef [2] cd f2 [2] cf f3 [2] d4 f5 [2] c8 f2 [2] d4 dd }

  condition:
    any of them
}