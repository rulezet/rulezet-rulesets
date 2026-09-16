rule TTP_XOR_QUAD_CurrentVersionRun_ba84 {
  strings:
    $key_ba84 = { e9 eb [2] cd e5 [2] e6 c9 [2] c8 eb [2] dc f0 [2] d3 ea [2] cd f7 [2] cf f6 [2] d4 f0 [2] c8 f7 [2] d4 d8 }

  condition:
    any of them
}