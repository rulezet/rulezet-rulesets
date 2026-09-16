rule TTP_XOR_QUAD_CurrentVersionRun_16ae {
  strings:
    $key_16ae = { 45 c1 [2] 61 cf [2] 4a e3 [2] 64 c1 [2] 70 da [2] 7f c0 [2] 61 dd [2] 63 dc [2] 78 da [2] 64 dd [2] 78 f2 }

  condition:
    any of them
}