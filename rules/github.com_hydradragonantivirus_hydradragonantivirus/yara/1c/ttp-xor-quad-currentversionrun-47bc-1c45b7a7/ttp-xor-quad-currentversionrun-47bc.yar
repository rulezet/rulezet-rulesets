rule TTP_XOR_QUAD_CurrentVersionRun_47bc {
  strings:
    $key_47bc = { 14 d3 [2] 30 dd [2] 1b f1 [2] 35 d3 [2] 21 c8 [2] 2e d2 [2] 30 cf [2] 32 ce [2] 29 c8 [2] 35 cf [2] 29 e0 }

  condition:
    any of them
}