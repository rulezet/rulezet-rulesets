rule TTP_XOR_QUAD_CurrentVersionRun_7dae {
  strings:
    $key_7dae = { 2e c1 [2] 0a cf [2] 21 e3 [2] 0f c1 [2] 1b da [2] 14 c0 [2] 0a dd [2] 08 dc [2] 13 da [2] 0f dd [2] 13 f2 }

  condition:
    any of them
}