rule TTP_XOR_QUAD_CurrentVersionRun_f09d {
  strings:
    $key_f09d = { a3 f2 [2] 87 fc [2] ac d0 [2] 82 f2 [2] 96 e9 [2] 99 f3 [2] 87 ee [2] 85 ef [2] 9e e9 [2] 82 ee [2] 9e c1 }

  condition:
    any of them
}