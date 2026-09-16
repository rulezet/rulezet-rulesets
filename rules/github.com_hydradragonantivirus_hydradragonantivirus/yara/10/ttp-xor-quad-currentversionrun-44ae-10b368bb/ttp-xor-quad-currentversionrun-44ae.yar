rule TTP_XOR_QUAD_CurrentVersionRun_44ae {
  strings:
    $key_44ae = { 17 c1 [2] 33 cf [2] 18 e3 [2] 36 c1 [2] 22 da [2] 2d c0 [2] 33 dd [2] 31 dc [2] 2a da [2] 36 dd [2] 2a f2 }

  condition:
    any of them
}