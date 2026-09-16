rule TTP_XOR_QUAD_CurrentVersionRun_788d {
  strings:
    $key_788d = { 2b e2 [2] 0f ec [2] 24 c0 [2] 0a e2 [2] 1e f9 [2] 11 e3 [2] 0f fe [2] 0d ff [2] 16 f9 [2] 0a fe [2] 16 d1 }

  condition:
    any of them
}