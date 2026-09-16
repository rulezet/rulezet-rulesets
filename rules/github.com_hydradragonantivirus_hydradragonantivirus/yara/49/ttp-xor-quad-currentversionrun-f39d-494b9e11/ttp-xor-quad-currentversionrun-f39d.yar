rule TTP_XOR_QUAD_CurrentVersionRun_f39d {
  strings:
    $key_f39d = { a0 f2 [2] 84 fc [2] af d0 [2] 81 f2 [2] 95 e9 [2] 9a f3 [2] 84 ee [2] 86 ef [2] 9d e9 [2] 81 ee [2] 9d c1 }

  condition:
    any of them
}