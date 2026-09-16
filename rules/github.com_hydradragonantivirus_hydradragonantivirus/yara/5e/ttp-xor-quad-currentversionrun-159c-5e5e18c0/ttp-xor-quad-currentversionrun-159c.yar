rule TTP_XOR_QUAD_CurrentVersionRun_159c {
  strings:
    $key_159c = { 46 f3 [2] 62 fd [2] 49 d1 [2] 67 f3 [2] 73 e8 [2] 7c f2 [2] 62 ef [2] 60 ee [2] 7b e8 [2] 67 ef [2] 7b c0 }

  condition:
    any of them
}