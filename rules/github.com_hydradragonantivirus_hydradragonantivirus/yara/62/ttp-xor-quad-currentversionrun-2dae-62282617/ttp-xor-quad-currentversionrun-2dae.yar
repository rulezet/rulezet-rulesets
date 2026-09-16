rule TTP_XOR_QUAD_CurrentVersionRun_2dae {
  strings:
    $key_2dae = { 7e c1 [2] 5a cf [2] 71 e3 [2] 5f c1 [2] 4b da [2] 44 c0 [2] 5a dd [2] 58 dc [2] 43 da [2] 5f dd [2] 43 f2 }

  condition:
    any of them
}