rule TTP_XOR_QUAD_CurrentVersionRun_598d {
  strings:
    $key_598d = { 0a e2 [2] 2e ec [2] 05 c0 [2] 2b e2 [2] 3f f9 [2] 30 e3 [2] 2e fe [2] 2c ff [2] 37 f9 [2] 2b fe [2] 37 d1 }

  condition:
    any of them
}