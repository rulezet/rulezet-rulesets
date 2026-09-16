rule TTP_XOR_QUAD_CurrentVersionRun_e281 {
  strings:
    $key_e281 = { b1 ee [2] 95 e0 [2] be cc [2] 90 ee [2] 84 f5 [2] 8b ef [2] 95 f2 [2] 97 f3 [2] 8c f5 [2] 90 f2 [2] 8c dd }

  condition:
    any of them
}