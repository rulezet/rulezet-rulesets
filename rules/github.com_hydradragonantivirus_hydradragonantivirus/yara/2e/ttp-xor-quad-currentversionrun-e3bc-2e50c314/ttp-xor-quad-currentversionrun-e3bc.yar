rule TTP_XOR_QUAD_CurrentVersionRun_e3bc {
  strings:
    $key_e3bc = { b0 d3 [2] 94 dd [2] bf f1 [2] 91 d3 [2] 85 c8 [2] 8a d2 [2] 94 cf [2] 96 ce [2] 8d c8 [2] 91 cf [2] 8d e0 }

  condition:
    any of them
}