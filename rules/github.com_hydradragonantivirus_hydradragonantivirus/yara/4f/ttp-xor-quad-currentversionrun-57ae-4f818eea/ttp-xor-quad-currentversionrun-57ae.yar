rule TTP_XOR_QUAD_CurrentVersionRun_57ae {
  strings:
    $key_57ae = { 04 c1 [2] 20 cf [2] 0b e3 [2] 25 c1 [2] 31 da [2] 3e c0 [2] 20 dd [2] 22 dc [2] 39 da [2] 25 dd [2] 39 f2 }

  condition:
    any of them
}