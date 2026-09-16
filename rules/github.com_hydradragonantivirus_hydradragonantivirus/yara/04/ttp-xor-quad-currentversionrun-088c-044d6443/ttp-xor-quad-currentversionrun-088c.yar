rule TTP_XOR_QUAD_CurrentVersionRun_088c {
  strings:
    $key_088c = { 5b e3 [2] 7f ed [2] 54 c1 [2] 7a e3 [2] 6e f8 [2] 61 e2 [2] 7f ff [2] 7d fe [2] 66 f8 [2] 7a ff [2] 66 d0 }

  condition:
    any of them
}