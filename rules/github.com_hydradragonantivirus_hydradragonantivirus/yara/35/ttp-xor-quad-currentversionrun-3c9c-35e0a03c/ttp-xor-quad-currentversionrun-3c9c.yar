rule TTP_XOR_QUAD_CurrentVersionRun_3c9c {
  strings:
    $key_3c9c = { 6f f3 [2] 4b fd [2] 60 d1 [2] 4e f3 [2] 5a e8 [2] 55 f2 [2] 4b ef [2] 49 ee [2] 52 e8 [2] 4e ef [2] 52 c0 }

  condition:
    any of them
}