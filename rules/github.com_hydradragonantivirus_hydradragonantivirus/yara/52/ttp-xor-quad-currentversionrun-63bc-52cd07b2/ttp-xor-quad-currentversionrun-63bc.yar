rule TTP_XOR_QUAD_CurrentVersionRun_63bc {
  strings:
    $key_63bc = { 30 d3 [2] 14 dd [2] 3f f1 [2] 11 d3 [2] 05 c8 [2] 0a d2 [2] 14 cf [2] 16 ce [2] 0d c8 [2] 11 cf [2] 0d e0 }

  condition:
    any of them
}