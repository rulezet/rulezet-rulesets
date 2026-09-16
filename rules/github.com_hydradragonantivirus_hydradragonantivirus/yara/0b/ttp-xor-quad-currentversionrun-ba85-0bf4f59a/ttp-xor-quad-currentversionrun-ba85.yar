rule TTP_XOR_QUAD_CurrentVersionRun_ba85 {
  strings:
    $key_ba85 = { e9 ea [2] cd e4 [2] e6 c8 [2] c8 ea [2] dc f1 [2] d3 eb [2] cd f6 [2] cf f7 [2] d4 f1 [2] c8 f6 [2] d4 d9 }

  condition:
    any of them
}