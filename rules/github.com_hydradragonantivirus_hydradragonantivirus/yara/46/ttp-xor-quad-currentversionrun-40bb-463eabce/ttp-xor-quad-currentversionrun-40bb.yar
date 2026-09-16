rule TTP_XOR_QUAD_CurrentVersionRun_40bb {
  strings:
    $key_40bb = { 13 d4 [2] 37 da [2] 1c f6 [2] 32 d4 [2] 26 cf [2] 29 d5 [2] 37 c8 [2] 35 c9 [2] 2e cf [2] 32 c8 [2] 2e e7 }

  condition:
    any of them
}