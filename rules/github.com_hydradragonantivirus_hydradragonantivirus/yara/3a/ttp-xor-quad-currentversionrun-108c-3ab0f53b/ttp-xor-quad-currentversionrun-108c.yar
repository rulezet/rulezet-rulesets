rule TTP_XOR_QUAD_CurrentVersionRun_108c {
  strings:
    $key_108c = { 43 e3 [2] 67 ed [2] 4c c1 [2] 62 e3 [2] 76 f8 [2] 79 e2 [2] 67 ff [2] 65 fe [2] 7e f8 [2] 62 ff [2] 7e d0 }

  condition:
    any of them
}