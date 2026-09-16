rule TTP_XOR_QUAD_CurrentVersionRun_1ebc {
  strings:
    $key_1ebc = { 4d d3 [2] 69 dd [2] 42 f1 [2] 6c d3 [2] 78 c8 [2] 77 d2 [2] 69 cf [2] 6b ce [2] 70 c8 [2] 6c cf [2] 70 e0 }

  condition:
    any of them
}