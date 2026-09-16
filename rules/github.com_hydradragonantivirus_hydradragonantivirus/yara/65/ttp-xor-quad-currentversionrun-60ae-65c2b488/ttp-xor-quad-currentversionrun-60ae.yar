rule TTP_XOR_QUAD_CurrentVersionRun_60ae {
  strings:
    $key_60ae = { 33 c1 [2] 17 cf [2] 3c e3 [2] 12 c1 [2] 06 da [2] 09 c0 [2] 17 dd [2] 15 dc [2] 0e da [2] 12 dd [2] 0e f2 }

  condition:
    any of them
}