rule TTP_XOR_QUAD_CurrentVersionRun_17bc {
  strings:
    $key_17bc = { 44 d3 [2] 60 dd [2] 4b f1 [2] 65 d3 [2] 71 c8 [2] 7e d2 [2] 60 cf [2] 62 ce [2] 79 c8 [2] 65 cf [2] 79 e0 }

  condition:
    any of them
}