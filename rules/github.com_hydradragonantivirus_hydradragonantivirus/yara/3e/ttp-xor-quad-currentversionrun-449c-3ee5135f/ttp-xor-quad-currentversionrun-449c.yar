rule TTP_XOR_QUAD_CurrentVersionRun_449c {
  strings:
    $key_449c = { 17 f3 [2] 33 fd [2] 18 d1 [2] 36 f3 [2] 22 e8 [2] 2d f2 [2] 33 ef [2] 31 ee [2] 2a e8 [2] 36 ef [2] 2a c0 }

  condition:
    any of them
}