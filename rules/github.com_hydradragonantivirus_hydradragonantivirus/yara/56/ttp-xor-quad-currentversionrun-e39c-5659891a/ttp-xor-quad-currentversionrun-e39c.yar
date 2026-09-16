rule TTP_XOR_QUAD_CurrentVersionRun_e39c {
  strings:
    $key_e39c = { b0 f3 [2] 94 fd [2] bf d1 [2] 91 f3 [2] 85 e8 [2] 8a f2 [2] 94 ef [2] 96 ee [2] 8d e8 [2] 91 ef [2] 8d c0 }

  condition:
    any of them
}