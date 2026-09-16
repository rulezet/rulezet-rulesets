rule TTP_XOR_QUAD_CurrentVersionRun_6781 {
  strings:
    $key_6781 = { 34 ee [2] 10 e0 [2] 3b cc [2] 15 ee [2] 01 f5 [2] 0e ef [2] 10 f2 [2] 12 f3 [2] 09 f5 [2] 15 f2 [2] 09 dd }

  condition:
    any of them
}