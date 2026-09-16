rule TTP_XOR_QUAD_CurrentVersionRun_ba80 {
  strings:
    $key_ba80 = { e9 ef [2] cd e1 [2] e6 cd [2] c8 ef [2] dc f4 [2] d3 ee [2] cd f3 [2] cf f2 [2] d4 f4 [2] c8 f3 [2] d4 dc }

  condition:
    any of them
}