rule TTP_XOR_QUAD_CurrentVersionRun_7fbc {
  strings:
    $key_7fbc = { 2c d3 [2] 08 dd [2] 23 f1 [2] 0d d3 [2] 19 c8 [2] 16 d2 [2] 08 cf [2] 0a ce [2] 11 c8 [2] 0d cf [2] 11 e0 }

  condition:
    any of them
}