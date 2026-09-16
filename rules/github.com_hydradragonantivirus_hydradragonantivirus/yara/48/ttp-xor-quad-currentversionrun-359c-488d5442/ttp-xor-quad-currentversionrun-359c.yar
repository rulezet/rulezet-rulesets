rule TTP_XOR_QUAD_CurrentVersionRun_359c {
  strings:
    $key_359c = { 66 f3 [2] 42 fd [2] 69 d1 [2] 47 f3 [2] 53 e8 [2] 5c f2 [2] 42 ef [2] 40 ee [2] 5b e8 [2] 47 ef [2] 5b c0 }

  condition:
    any of them
}