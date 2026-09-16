rule TTP_XOR_QUAD_CurrentVersionRun_61bc {
  strings:
    $key_61bc = { 32 d3 [2] 16 dd [2] 3d f1 [2] 13 d3 [2] 07 c8 [2] 08 d2 [2] 16 cf [2] 14 ce [2] 0f c8 [2] 13 cf [2] 0f e0 }

  condition:
    any of them
}