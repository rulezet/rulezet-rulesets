rule TTP_XOR_QUAD_CurrentVersionRun_228c {
  strings:
    $key_228c = { 71 e3 [2] 55 ed [2] 7e c1 [2] 50 e3 [2] 44 f8 [2] 4b e2 [2] 55 ff [2] 57 fe [2] 4c f8 [2] 50 ff [2] 4c d0 }

  condition:
    any of them
}