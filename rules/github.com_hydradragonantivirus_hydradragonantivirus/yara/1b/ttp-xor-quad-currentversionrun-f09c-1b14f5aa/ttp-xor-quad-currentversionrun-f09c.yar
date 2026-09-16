rule TTP_XOR_QUAD_CurrentVersionRun_f09c {
  strings:
    $key_f09c = { a3 f3 [2] 87 fd [2] ac d1 [2] 82 f3 [2] 96 e8 [2] 99 f2 [2] 87 ef [2] 85 ee [2] 9e e8 [2] 82 ef [2] 9e c0 }

  condition:
    any of them
}