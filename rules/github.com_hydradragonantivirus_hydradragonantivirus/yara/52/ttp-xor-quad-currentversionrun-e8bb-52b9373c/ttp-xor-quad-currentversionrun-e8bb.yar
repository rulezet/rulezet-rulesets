rule TTP_XOR_QUAD_CurrentVersionRun_e8bb {
  strings:
    $key_e8bb = { bb d4 [2] 9f da [2] b4 f6 [2] 9a d4 [2] 8e cf [2] 81 d5 [2] 9f c8 [2] 9d c9 [2] 86 cf [2] 9a c8 [2] 86 e7 }

  condition:
    any of them
}