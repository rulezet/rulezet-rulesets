rule TTP_XOR_QUAD_CurrentVersionRun_659c {
  strings:
    $key_659c = { 36 f3 [2] 12 fd [2] 39 d1 [2] 17 f3 [2] 03 e8 [2] 0c f2 [2] 12 ef [2] 10 ee [2] 0b e8 [2] 17 ef [2] 0b c0 }

  condition:
    any of them
}