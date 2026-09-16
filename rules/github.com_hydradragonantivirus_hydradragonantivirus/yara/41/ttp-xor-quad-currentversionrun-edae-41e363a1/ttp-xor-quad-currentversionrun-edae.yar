rule TTP_XOR_QUAD_CurrentVersionRun_edae {
  strings:
    $key_edae = { be c1 [2] 9a cf [2] b1 e3 [2] 9f c1 [2] 8b da [2] 84 c0 [2] 9a dd [2] 98 dc [2] 83 da [2] 9f dd [2] 83 f2 }

  condition:
    any of them
}