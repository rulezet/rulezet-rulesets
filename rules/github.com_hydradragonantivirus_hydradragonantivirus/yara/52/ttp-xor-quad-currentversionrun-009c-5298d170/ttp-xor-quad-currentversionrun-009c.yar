rule TTP_XOR_QUAD_CurrentVersionRun_009c {
  strings:
    $key_009c = { 53 f3 [2] 77 fd [2] 5c d1 [2] 72 f3 [2] 66 e8 [2] 69 f2 [2] 77 ef [2] 75 ee [2] 6e e8 [2] 72 ef [2] 6e c0 }

  condition:
    any of them
}