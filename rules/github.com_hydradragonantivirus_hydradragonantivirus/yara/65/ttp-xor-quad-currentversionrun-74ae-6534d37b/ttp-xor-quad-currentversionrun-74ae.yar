rule TTP_XOR_QUAD_CurrentVersionRun_74ae {
  strings:
    $key_74ae = { 27 c1 [2] 03 cf [2] 28 e3 [2] 06 c1 [2] 12 da [2] 1d c0 [2] 03 dd [2] 01 dc [2] 1a da [2] 06 dd [2] 1a f2 }

  condition:
    any of them
}