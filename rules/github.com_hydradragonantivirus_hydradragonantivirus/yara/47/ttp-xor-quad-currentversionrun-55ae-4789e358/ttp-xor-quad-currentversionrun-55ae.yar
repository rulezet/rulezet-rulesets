rule TTP_XOR_QUAD_CurrentVersionRun_55ae {
  strings:
    $key_55ae = { 06 c1 [2] 22 cf [2] 09 e3 [2] 27 c1 [2] 33 da [2] 3c c0 [2] 22 dd [2] 20 dc [2] 3b da [2] 27 dd [2] 3b f2 }

  condition:
    any of them
}