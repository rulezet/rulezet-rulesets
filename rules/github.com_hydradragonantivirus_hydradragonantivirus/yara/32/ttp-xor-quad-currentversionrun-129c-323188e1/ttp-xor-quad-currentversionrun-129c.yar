rule TTP_XOR_QUAD_CurrentVersionRun_129c {
  strings:
    $key_129c = { 41 f3 [2] 65 fd [2] 4e d1 [2] 60 f3 [2] 74 e8 [2] 7b f2 [2] 65 ef [2] 67 ee [2] 7c e8 [2] 60 ef [2] 7c c0 }

  condition:
    any of them
}