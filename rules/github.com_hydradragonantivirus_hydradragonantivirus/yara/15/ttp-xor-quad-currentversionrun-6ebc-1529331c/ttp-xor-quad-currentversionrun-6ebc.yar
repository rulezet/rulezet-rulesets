rule TTP_XOR_QUAD_CurrentVersionRun_6ebc {
  strings:
    $key_6ebc = { 3d d3 [2] 19 dd [2] 32 f1 [2] 1c d3 [2] 08 c8 [2] 07 d2 [2] 19 cf [2] 1b ce [2] 00 c8 [2] 1c cf [2] 00 e0 }

  condition:
    any of them
}