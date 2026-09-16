rule TTP_XOR_QUAD_CurrentVersionRun_3dae {
  strings:
    $key_3dae = { 6e c1 [2] 4a cf [2] 61 e3 [2] 4f c1 [2] 5b da [2] 54 c0 [2] 4a dd [2] 48 dc [2] 53 da [2] 4f dd [2] 53 f2 }

  condition:
    any of them
}