rule TTP_XOR_QUAD_CurrentVersionRun_b791 {
  strings:
    $key_b791 = { e4 fe [2] c0 f0 [2] eb dc [2] c5 fe [2] d1 e5 [2] de ff [2] c0 e2 [2] c2 e3 [2] d9 e5 [2] c5 e2 [2] d9 cd }

  condition:
    any of them
}