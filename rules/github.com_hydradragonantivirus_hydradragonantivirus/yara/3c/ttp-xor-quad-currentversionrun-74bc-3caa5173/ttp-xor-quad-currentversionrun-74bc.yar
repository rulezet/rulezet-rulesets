rule TTP_XOR_QUAD_CurrentVersionRun_74bc {
  strings:
    $key_74bc = { 27 d3 [2] 03 dd [2] 28 f1 [2] 06 d3 [2] 12 c8 [2] 1d d2 [2] 03 cf [2] 01 ce [2] 1a c8 [2] 06 cf [2] 1a e0 }

  condition:
    any of them
}