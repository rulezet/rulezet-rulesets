rule TTP_XOR_QUAD_CurrentVersionRun_13bb {
  strings:
    $key_13bb = { 40 d4 [2] 64 da [2] 4f f6 [2] 61 d4 [2] 75 cf [2] 7a d5 [2] 64 c8 [2] 66 c9 [2] 7d cf [2] 61 c8 [2] 7d e7 }

  condition:
    any of them
}