rule TTP_XOR_QUAD_CurrentVersionRun_519c {
  strings:
    $key_519c = { 02 f3 [2] 26 fd [2] 0d d1 [2] 23 f3 [2] 37 e8 [2] 38 f2 [2] 26 ef [2] 24 ee [2] 3f e8 [2] 23 ef [2] 3f c0 }

  condition:
    any of them
}