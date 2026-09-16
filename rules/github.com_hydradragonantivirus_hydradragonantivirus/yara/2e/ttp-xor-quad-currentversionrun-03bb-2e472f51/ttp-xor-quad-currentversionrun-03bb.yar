rule TTP_XOR_QUAD_CurrentVersionRun_03bb {
  strings:
    $key_03bb = { 50 d4 [2] 74 da [2] 5f f6 [2] 71 d4 [2] 65 cf [2] 6a d5 [2] 74 c8 [2] 76 c9 [2] 6d cf [2] 71 c8 [2] 6d e7 }

  condition:
    any of them
}