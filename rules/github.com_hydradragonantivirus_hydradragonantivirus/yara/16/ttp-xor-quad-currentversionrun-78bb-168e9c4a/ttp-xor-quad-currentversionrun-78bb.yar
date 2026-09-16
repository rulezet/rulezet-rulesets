rule TTP_XOR_QUAD_CurrentVersionRun_78bb {
  strings:
    $key_78bb = { 2b d4 [2] 0f da [2] 24 f6 [2] 0a d4 [2] 1e cf [2] 11 d5 [2] 0f c8 [2] 0d c9 [2] 16 cf [2] 0a c8 [2] 16 e7 }

  condition:
    any of them
}