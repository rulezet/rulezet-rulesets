rule TTP_XOR_QUAD_CurrentVersionRun_77ae {
  strings:
    $key_77ae = { 24 c1 [2] 00 cf [2] 2b e3 [2] 05 c1 [2] 11 da [2] 1e c0 [2] 00 dd [2] 02 dc [2] 19 da [2] 05 dd [2] 19 f2 }

  condition:
    any of them
}