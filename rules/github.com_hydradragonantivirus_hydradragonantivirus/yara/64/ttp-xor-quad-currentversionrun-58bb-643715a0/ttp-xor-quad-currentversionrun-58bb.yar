rule TTP_XOR_QUAD_CurrentVersionRun_58bb {
  strings:
    $key_58bb = { 0b d4 [2] 2f da [2] 04 f6 [2] 2a d4 [2] 3e cf [2] 31 d5 [2] 2f c8 [2] 2d c9 [2] 36 cf [2] 2a c8 [2] 36 e7 }

  condition:
    any of them
}