rule TTP_XOR_QUAD_CurrentVersionRun_4c9c {
  strings:
    $key_4c9c = { 1f f3 [2] 3b fd [2] 10 d1 [2] 3e f3 [2] 2a e8 [2] 25 f2 [2] 3b ef [2] 39 ee [2] 22 e8 [2] 3e ef [2] 22 c0 }

  condition:
    any of them
}