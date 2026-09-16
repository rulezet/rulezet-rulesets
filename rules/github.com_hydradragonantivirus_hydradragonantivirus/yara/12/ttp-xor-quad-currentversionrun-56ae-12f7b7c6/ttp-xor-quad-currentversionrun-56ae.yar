rule TTP_XOR_QUAD_CurrentVersionRun_56ae {
  strings:
    $key_56ae = { 05 c1 [2] 21 cf [2] 0a e3 [2] 24 c1 [2] 30 da [2] 3f c0 [2] 21 dd [2] 23 dc [2] 38 da [2] 24 dd [2] 38 f2 }

  condition:
    any of them
}