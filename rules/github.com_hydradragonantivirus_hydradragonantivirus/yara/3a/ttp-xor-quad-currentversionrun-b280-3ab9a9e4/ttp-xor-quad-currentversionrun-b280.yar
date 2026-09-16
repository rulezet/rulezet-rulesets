rule TTP_XOR_QUAD_CurrentVersionRun_b280 {
  strings:
    $key_b280 = { e1 ef [2] c5 e1 [2] ee cd [2] c0 ef [2] d4 f4 [2] db ee [2] c5 f3 [2] c7 f2 [2] dc f4 [2] c0 f3 [2] dc dc }

  condition:
    any of them
}