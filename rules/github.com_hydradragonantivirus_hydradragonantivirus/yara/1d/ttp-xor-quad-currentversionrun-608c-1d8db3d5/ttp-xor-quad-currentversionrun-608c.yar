rule TTP_XOR_QUAD_CurrentVersionRun_608c {
  strings:
    $key_608c = { 33 e3 [2] 17 ed [2] 3c c1 [2] 12 e3 [2] 06 f8 [2] 09 e2 [2] 17 ff [2] 15 fe [2] 0e f8 [2] 12 ff [2] 0e d0 }

  condition:
    any of them
}