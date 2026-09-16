rule TTP_XOR_QUAD_CurrentVersionRun_469c {
  strings:
    $key_469c = { 15 f3 [2] 31 fd [2] 1a d1 [2] 34 f3 [2] 20 e8 [2] 2f f2 [2] 31 ef [2] 33 ee [2] 28 e8 [2] 34 ef [2] 28 c0 }

  condition:
    any of them
}