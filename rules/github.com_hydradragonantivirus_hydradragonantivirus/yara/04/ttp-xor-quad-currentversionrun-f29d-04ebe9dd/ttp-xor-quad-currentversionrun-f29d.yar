rule TTP_XOR_QUAD_CurrentVersionRun_f29d {
  strings:
    $key_f29d = { a1 f2 [2] 85 fc [2] ae d0 [2] 80 f2 [2] 94 e9 [2] 9b f3 [2] 85 ee [2] 87 ef [2] 9c e9 [2] 80 ee [2] 9c c1 }

  condition:
    any of them
}