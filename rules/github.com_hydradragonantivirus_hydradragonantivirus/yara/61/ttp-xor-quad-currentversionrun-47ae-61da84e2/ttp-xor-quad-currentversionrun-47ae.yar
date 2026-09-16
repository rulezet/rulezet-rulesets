rule TTP_XOR_QUAD_CurrentVersionRun_47ae {
  strings:
    $key_47ae = { 14 c1 [2] 30 cf [2] 1b e3 [2] 35 c1 [2] 21 da [2] 2e c0 [2] 30 dd [2] 32 dc [2] 29 da [2] 35 dd [2] 29 f2 }

  condition:
    any of them
}