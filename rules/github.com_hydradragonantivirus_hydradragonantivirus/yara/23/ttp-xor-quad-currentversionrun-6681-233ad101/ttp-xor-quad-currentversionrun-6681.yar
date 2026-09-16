rule TTP_XOR_QUAD_CurrentVersionRun_6681 {
  strings:
    $key_6681 = { 35 ee [2] 11 e0 [2] 3a cc [2] 14 ee [2] 00 f5 [2] 0f ef [2] 11 f2 [2] 13 f3 [2] 08 f5 [2] 14 f2 [2] 08 dd }

  condition:
    any of them
}