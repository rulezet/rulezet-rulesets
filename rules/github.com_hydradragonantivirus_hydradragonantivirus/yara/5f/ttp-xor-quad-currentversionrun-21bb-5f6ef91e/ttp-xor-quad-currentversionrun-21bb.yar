rule TTP_XOR_QUAD_CurrentVersionRun_21bb {
  strings:
    $key_21bb = { 72 d4 [2] 56 da [2] 7d f6 [2] 53 d4 [2] 47 cf [2] 48 d5 [2] 56 c8 [2] 54 c9 [2] 4f cf [2] 53 c8 [2] 4f e7 }

  condition:
    any of them
}