rule TTP_XOR_QUAD_CurrentVersionRun_4681 {
  strings:
    $key_4681 = { 15 ee [2] 31 e0 [2] 1a cc [2] 34 ee [2] 20 f5 [2] 2f ef [2] 31 f2 [2] 33 f3 [2] 28 f5 [2] 34 f2 [2] 28 dd }

  condition:
    any of them
}