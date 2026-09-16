rule TTP_XOR_QUAD_CurrentVersionRun_219c {
  strings:
    $key_219c = { 72 f3 [2] 56 fd [2] 7d d1 [2] 53 f3 [2] 47 e8 [2] 48 f2 [2] 56 ef [2] 54 ee [2] 4f e8 [2] 53 ef [2] 4f c0 }

  condition:
    any of them
}