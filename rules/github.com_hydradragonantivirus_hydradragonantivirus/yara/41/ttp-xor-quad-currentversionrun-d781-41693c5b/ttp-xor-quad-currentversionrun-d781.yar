rule TTP_XOR_QUAD_CurrentVersionRun_d781 {
  strings:
    $key_d781 = { 84 ee [2] a0 e0 [2] 8b cc [2] a5 ee [2] b1 f5 [2] be ef [2] a0 f2 [2] a2 f3 [2] b9 f5 [2] a5 f2 [2] b9 dd }

  condition:
    any of them
}