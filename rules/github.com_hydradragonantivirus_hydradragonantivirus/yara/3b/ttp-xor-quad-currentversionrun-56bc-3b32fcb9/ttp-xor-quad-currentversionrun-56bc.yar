rule TTP_XOR_QUAD_CurrentVersionRun_56bc {
  strings:
    $key_56bc = { 05 d3 [2] 21 dd [2] 0a f1 [2] 24 d3 [2] 30 c8 [2] 3f d2 [2] 21 cf [2] 23 ce [2] 38 c8 [2] 24 cf [2] 38 e0 }

  condition:
    any of them
}