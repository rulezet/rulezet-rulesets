rule TTP_XOR_QUAD_CurrentVersionRun_31bc {
  strings:
    $key_31bc = { 62 d3 [2] 46 dd [2] 6d f1 [2] 43 d3 [2] 57 c8 [2] 58 d2 [2] 46 cf [2] 44 ce [2] 5f c8 [2] 43 cf [2] 5f e0 }

  condition:
    any of them
}