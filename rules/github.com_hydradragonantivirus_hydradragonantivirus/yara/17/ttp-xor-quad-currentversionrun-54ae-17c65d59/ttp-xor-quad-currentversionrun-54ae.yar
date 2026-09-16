rule TTP_XOR_QUAD_CurrentVersionRun_54ae {
  strings:
    $key_54ae = { 07 c1 [2] 23 cf [2] 08 e3 [2] 26 c1 [2] 32 da [2] 3d c0 [2] 23 dd [2] 21 dc [2] 3a da [2] 26 dd [2] 3a f2 }

  condition:
    any of them
}