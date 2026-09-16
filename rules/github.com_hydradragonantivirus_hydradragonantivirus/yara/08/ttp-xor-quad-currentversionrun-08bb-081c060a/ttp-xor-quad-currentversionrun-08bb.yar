rule TTP_XOR_QUAD_CurrentVersionRun_08bb {
  strings:
    $key_08bb = { 5b d4 [2] 7f da [2] 54 f6 [2] 7a d4 [2] 6e cf [2] 61 d5 [2] 7f c8 [2] 7d c9 [2] 66 cf [2] 7a c8 [2] 66 e7 }

  condition:
    any of them
}