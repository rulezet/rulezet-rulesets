rule TTP_XOR_QUAD_CurrentVersionRun_188c {
  strings:
    $key_188c = { 4b e3 [2] 6f ed [2] 44 c1 [2] 6a e3 [2] 7e f8 [2] 71 e2 [2] 6f ff [2] 6d fe [2] 76 f8 [2] 6a ff [2] 76 d0 }

  condition:
    any of them
}