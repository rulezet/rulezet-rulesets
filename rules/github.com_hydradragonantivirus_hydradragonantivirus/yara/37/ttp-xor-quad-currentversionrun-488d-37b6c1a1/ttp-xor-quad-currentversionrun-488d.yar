rule TTP_XOR_QUAD_CurrentVersionRun_488d {
  strings:
    $key_488d = { 1b e2 [2] 3f ec [2] 14 c0 [2] 3a e2 [2] 2e f9 [2] 21 e3 [2] 3f fe [2] 3d ff [2] 26 f9 [2] 3a fe [2] 26 d1 }

  condition:
    any of them
}