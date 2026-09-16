rule TTP_XOR_QUAD_CurrentVersionRun_b287 {
  strings:
    $key_b287 = { e1 e8 [2] c5 e6 [2] ee ca [2] c0 e8 [2] d4 f3 [2] db e9 [2] c5 f4 [2] c7 f5 [2] dc f3 [2] c0 f4 [2] dc db }

  condition:
    any of them
}