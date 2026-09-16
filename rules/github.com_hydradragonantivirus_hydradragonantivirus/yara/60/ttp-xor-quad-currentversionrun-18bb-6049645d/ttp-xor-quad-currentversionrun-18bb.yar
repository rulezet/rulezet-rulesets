rule TTP_XOR_QUAD_CurrentVersionRun_18bb {
  strings:
    $key_18bb = { 4b d4 [2] 6f da [2] 44 f6 [2] 6a d4 [2] 7e cf [2] 71 d5 [2] 6f c8 [2] 6d c9 [2] 76 cf [2] 6a c8 [2] 76 e7 }

  condition:
    any of them
}