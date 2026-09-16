rule TTP_XOR_QUAD_CurrentVersionRun_fc9c {
  strings:
    $key_fc9c = { af f3 [2] 8b fd [2] a0 d1 [2] 8e f3 [2] 9a e8 [2] 95 f2 [2] 8b ef [2] 89 ee [2] 92 e8 [2] 8e ef [2] 92 c0 }

  condition:
    any of them
}