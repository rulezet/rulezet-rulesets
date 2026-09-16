rule TTP_XOR_QUAD_CurrentVersionRun_2c9c {
  strings:
    $key_2c9c = { 7f f3 [2] 5b fd [2] 70 d1 [2] 5e f3 [2] 4a e8 [2] 45 f2 [2] 5b ef [2] 59 ee [2] 42 e8 [2] 5e ef [2] 42 c0 }

  condition:
    any of them
}