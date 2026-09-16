rule TTP_XOR_QUAD_CurrentVersionRun_688c {
  strings:
    $key_688c = { 3b e3 [2] 1f ed [2] 34 c1 [2] 1a e3 [2] 0e f8 [2] 01 e2 [2] 1f ff [2] 1d fe [2] 06 f8 [2] 1a ff [2] 06 d0 }

  condition:
    any of them
}