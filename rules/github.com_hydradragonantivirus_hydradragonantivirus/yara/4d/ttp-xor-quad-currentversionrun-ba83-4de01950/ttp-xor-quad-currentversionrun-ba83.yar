rule TTP_XOR_QUAD_CurrentVersionRun_ba83 {
  strings:
    $key_ba83 = { e9 ec [2] cd e2 [2] e6 ce [2] c8 ec [2] dc f7 [2] d3 ed [2] cd f0 [2] cf f1 [2] d4 f7 [2] c8 f0 [2] d4 df }

  condition:
    any of them
}