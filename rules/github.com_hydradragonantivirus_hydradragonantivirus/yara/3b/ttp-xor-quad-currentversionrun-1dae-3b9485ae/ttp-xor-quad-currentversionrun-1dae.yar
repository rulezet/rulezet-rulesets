rule TTP_XOR_QUAD_CurrentVersionRun_1dae {
  strings:
    $key_1dae = { 4e c1 [2] 6a cf [2] 41 e3 [2] 6f c1 [2] 7b da [2] 74 c0 [2] 6a dd [2] 68 dc [2] 73 da [2] 6f dd [2] 73 f2 }

  condition:
    any of them
}