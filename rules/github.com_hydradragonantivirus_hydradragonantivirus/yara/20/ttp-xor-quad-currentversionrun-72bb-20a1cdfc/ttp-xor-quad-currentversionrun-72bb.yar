rule TTP_XOR_QUAD_CurrentVersionRun_72bb {
  strings:
    $key_72bb = { 21 d4 [2] 05 da [2] 2e f6 [2] 00 d4 [2] 14 cf [2] 1b d5 [2] 05 c8 [2] 07 c9 [2] 1c cf [2] 00 c8 [2] 1c e7 }

  condition:
    any of them
}