rule TTP_XOR_QUAD_CurrentVersionRun_4fbc {
  strings:
    $key_4fbc = { 1c d3 [2] 38 dd [2] 13 f1 [2] 3d d3 [2] 29 c8 [2] 26 d2 [2] 38 cf [2] 3a ce [2] 21 c8 [2] 3d cf [2] 21 e0 }

  condition:
    any of them
}