rule TTP_XOR_QUAD_CurrentVersionRun_179c {
  strings:
    $key_179c = { 44 f3 [2] 60 fd [2] 4b d1 [2] 65 f3 [2] 71 e8 [2] 7e f2 [2] 60 ef [2] 62 ee [2] 79 e8 [2] 65 ef [2] 79 c0 }

  condition:
    any of them
}