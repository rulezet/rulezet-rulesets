rule TTP_XOR_QUAD_CurrentVersionRun_eebc {
  strings:
    $key_eebc = { bd d3 [2] 99 dd [2] b2 f1 [2] 9c d3 [2] 88 c8 [2] 87 d2 [2] 99 cf [2] 9b ce [2] 80 c8 [2] 9c cf [2] 80 e0 }

  condition:
    any of them
}