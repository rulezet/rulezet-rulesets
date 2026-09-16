rule TTP_XOR_QUAD_CurrentVersionRun_ba9b {
  strings:
    $key_ba9b = { e9 f4 [2] cd fa [2] e6 d6 [2] c8 f4 [2] dc ef [2] d3 f5 [2] cd e8 [2] cf e9 [2] d4 ef [2] c8 e8 [2] d4 c7 }

  condition:
    any of them
}