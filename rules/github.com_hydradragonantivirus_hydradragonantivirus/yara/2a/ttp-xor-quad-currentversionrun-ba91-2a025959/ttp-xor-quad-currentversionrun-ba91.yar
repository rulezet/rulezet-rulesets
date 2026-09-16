rule TTP_XOR_QUAD_CurrentVersionRun_ba91 {
  strings:
    $key_ba91 = { e9 fe [2] cd f0 [2] e6 dc [2] c8 fe [2] dc e5 [2] d3 ff [2] cd e2 [2] cf e3 [2] d4 e5 [2] c8 e2 [2] d4 cd }

  condition:
    any of them
}