rule TTP_XOR_QUAD_CurrentVersionRun_22ae {
  strings:
    $key_22ae = { 71 c1 [2] 55 cf [2] 7e e3 [2] 50 c1 [2] 44 da [2] 4b c0 [2] 55 dd [2] 57 dc [2] 4c da [2] 50 dd [2] 4c f2 }

  condition:
    any of them
}