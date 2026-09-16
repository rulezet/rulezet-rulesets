rule TTP_XOR_QUAD_CurrentVersionRun_6dae {
  strings:
    $key_6dae = { 3e c1 [2] 1a cf [2] 31 e3 [2] 1f c1 [2] 0b da [2] 04 c0 [2] 1a dd [2] 18 dc [2] 03 da [2] 1f dd [2] 03 f2 }

  condition:
    any of them
}