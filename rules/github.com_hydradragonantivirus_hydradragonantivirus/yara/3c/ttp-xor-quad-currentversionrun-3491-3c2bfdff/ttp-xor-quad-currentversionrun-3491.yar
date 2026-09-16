rule TTP_XOR_QUAD_CurrentVersionRun_3491 {
  strings:
    $key_3491 = { 67 fe [2] 43 f0 [2] 68 dc [2] 46 fe [2] 52 e5 [2] 5d ff [2] 43 e2 [2] 41 e3 [2] 5a e5 [2] 46 e2 [2] 5a cd }

  condition:
    any of them
}