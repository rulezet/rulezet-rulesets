rule TTP_XOR_QUAD_CurrentVersionRun_ba87 {
  strings:
    $key_ba87 = { e9 e8 [2] cd e6 [2] e6 ca [2] c8 e8 [2] dc f3 [2] d3 e9 [2] cd f4 [2] cf f5 [2] d4 f3 [2] c8 f4 [2] d4 db }

  condition:
    any of them
}