rule TTP_XOR_QUAD_CurrentVersionRun_5491 {
  strings:
    $key_5491 = { 07 fe [2] 23 f0 [2] 08 dc [2] 26 fe [2] 32 e5 [2] 3d ff [2] 23 e2 [2] 21 e3 [2] 3a e5 [2] 26 e2 [2] 3a cd }

  condition:
    any of them
}