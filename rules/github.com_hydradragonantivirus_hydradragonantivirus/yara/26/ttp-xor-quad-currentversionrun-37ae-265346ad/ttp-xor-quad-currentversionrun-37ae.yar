rule TTP_XOR_QUAD_CurrentVersionRun_37ae {
  strings:
    $key_37ae = { 64 c1 [2] 40 cf [2] 6b e3 [2] 45 c1 [2] 51 da [2] 5e c0 [2] 40 dd [2] 42 dc [2] 59 da [2] 45 dd [2] 59 f2 }

  condition:
    any of them
}