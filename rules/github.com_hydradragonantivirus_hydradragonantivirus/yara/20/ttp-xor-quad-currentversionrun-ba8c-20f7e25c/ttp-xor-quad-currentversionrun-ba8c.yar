rule TTP_XOR_QUAD_CurrentVersionRun_ba8c {
  strings:
    $key_ba8c = { e9 e3 [2] cd ed [2] e6 c1 [2] c8 e3 [2] dc f8 [2] d3 e2 [2] cd ff [2] cf fe [2] d4 f8 [2] c8 ff [2] d4 d0 }

  condition:
    any of them
}