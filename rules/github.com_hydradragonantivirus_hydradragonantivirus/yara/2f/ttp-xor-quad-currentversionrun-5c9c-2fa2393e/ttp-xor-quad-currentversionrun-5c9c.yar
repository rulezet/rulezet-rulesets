rule TTP_XOR_QUAD_CurrentVersionRun_5c9c {
  strings:
    $key_5c9c = { 0f f3 [2] 2b fd [2] 00 d1 [2] 2e f3 [2] 3a e8 [2] 35 f2 [2] 2b ef [2] 29 ee [2] 32 e8 [2] 2e ef [2] 32 c0 }

  condition:
    any of them
}