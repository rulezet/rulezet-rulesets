rule TTP_XOR_QUAD_CurrentVersionRun_53bc {
  strings:
    $key_53bc = { 00 d3 [2] 24 dd [2] 0f f1 [2] 21 d3 [2] 35 c8 [2] 3a d2 [2] 24 cf [2] 26 ce [2] 3d c8 [2] 21 cf [2] 3d e0 }

  condition:
    any of them
}