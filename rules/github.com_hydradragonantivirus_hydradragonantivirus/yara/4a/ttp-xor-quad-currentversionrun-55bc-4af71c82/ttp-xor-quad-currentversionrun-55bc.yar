rule TTP_XOR_QUAD_CurrentVersionRun_55bc {
  strings:
    $key_55bc = { 06 d3 [2] 22 dd [2] 09 f1 [2] 27 d3 [2] 33 c8 [2] 3c d2 [2] 22 cf [2] 20 ce [2] 3b c8 [2] 27 cf [2] 3b e0 }

  condition:
    any of them
}