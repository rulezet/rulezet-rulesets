rule TTP_XOR_QUAD_CurrentVersionRun_7681 {
  strings:
    $key_7681 = { 25 ee [2] 01 e0 [2] 2a cc [2] 04 ee [2] 10 f5 [2] 1f ef [2] 01 f2 [2] 03 f3 [2] 18 f5 [2] 04 f2 [2] 18 dd }

  condition:
    any of them
}