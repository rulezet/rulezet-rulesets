rule TTP_XOR_QUAD_CurrentVersionRun_27ae {
  strings:
    $key_27ae = { 74 c1 [2] 50 cf [2] 7b e3 [2] 55 c1 [2] 41 da [2] 4e c0 [2] 50 dd [2] 52 dc [2] 49 da [2] 55 dd [2] 49 f2 }

  condition:
    any of them
}