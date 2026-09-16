rule TTP_XOR_QUAD_CurrentVersionRun_e19c {
  strings:
    $key_e19c = { b2 f3 [2] 96 fd [2] bd d1 [2] 93 f3 [2] 87 e8 [2] 88 f2 [2] 96 ef [2] 94 ee [2] 8f e8 [2] 93 ef [2] 8f c0 }

  condition:
    any of them
}