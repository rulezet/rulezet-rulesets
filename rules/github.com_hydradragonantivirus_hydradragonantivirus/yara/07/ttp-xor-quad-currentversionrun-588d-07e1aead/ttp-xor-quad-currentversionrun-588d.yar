rule TTP_XOR_QUAD_CurrentVersionRun_588d {
  strings:
    $key_588d = { 0b e2 [2] 2f ec [2] 04 c0 [2] 2a e2 [2] 3e f9 [2] 31 e3 [2] 2f fe [2] 2d ff [2] 36 f9 [2] 2a fe [2] 36 d1 }

  condition:
    any of them
}