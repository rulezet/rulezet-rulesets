rule TTP_XOR_QUAD_CurrentVersionRun_788c {
  strings:
    $key_788c = { 2b e3 [2] 0f ed [2] 24 c1 [2] 0a e3 [2] 1e f8 [2] 11 e2 [2] 0f ff [2] 0d fe [2] 16 f8 [2] 0a ff [2] 16 d0 }

  condition:
    any of them
}