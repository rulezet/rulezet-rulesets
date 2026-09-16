rule TTP_XOR_QUAD_CurrentVersionRun_65bc {
  strings:
    $key_65bc = { 36 d3 [2] 12 dd [2] 39 f1 [2] 17 d3 [2] 03 c8 [2] 0c d2 [2] 12 cf [2] 10 ce [2] 0b c8 [2] 17 cf [2] 0b e0 }

  condition:
    any of them
}