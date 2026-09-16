rule TTP_XOR_QUAD_CurrentVersionRun_f29c {
  strings:
    $key_f29c = { a1 f3 [2] 85 fd [2] ae d1 [2] 80 f3 [2] 94 e8 [2] 9b f2 [2] 85 ef [2] 87 ee [2] 9c e8 [2] 80 ef [2] 9c c0 }

  condition:
    any of them
}