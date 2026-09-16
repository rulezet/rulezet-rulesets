rule TTP_XOR_QUAD_CurrentVersionRun_17ae {
  strings:
    $key_17ae = { 44 c1 [2] 60 cf [2] 4b e3 [2] 65 c1 [2] 71 da [2] 7e c0 [2] 60 dd [2] 62 dc [2] 79 da [2] 65 dd [2] 79 f2 }

  condition:
    any of them
}