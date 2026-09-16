rule TTP_XOR_QUAD_CurrentVersionRun_76ae {
  strings:
    $key_76ae = { 25 c1 [2] 01 cf [2] 2a e3 [2] 04 c1 [2] 10 da [2] 1f c0 [2] 01 dd [2] 03 dc [2] 18 da [2] 04 dd [2] 18 f2 }

  condition:
    any of them
}