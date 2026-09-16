rule TTP_XOR_QUAD_CurrentVersionRun_07ae {
  strings:
    $key_07ae = { 54 c1 [2] 70 cf [2] 5b e3 [2] 75 c1 [2] 61 da [2] 6e c0 [2] 70 dd [2] 72 dc [2] 69 da [2] 75 dd [2] 69 f2 }

  condition:
    any of them
}