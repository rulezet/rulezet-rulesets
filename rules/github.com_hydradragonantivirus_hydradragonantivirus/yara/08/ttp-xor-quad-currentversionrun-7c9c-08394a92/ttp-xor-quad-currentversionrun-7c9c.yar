rule TTP_XOR_QUAD_CurrentVersionRun_7c9c {
  strings:
    $key_7c9c = { 2f f3 [2] 0b fd [2] 20 d1 [2] 0e f3 [2] 1a e8 [2] 15 f2 [2] 0b ef [2] 09 ee [2] 12 e8 [2] 0e ef [2] 12 c0 }

  condition:
    any of them
}