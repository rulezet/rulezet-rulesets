rule TTP_XOR_QUAD_CurrentVersionRun_06bb {
  strings:
    $key_06bb = { 55 d4 [2] 71 da [2] 5a f6 [2] 74 d4 [2] 60 cf [2] 6f d5 [2] 71 c8 [2] 73 c9 [2] 68 cf [2] 74 c8 [2] 68 e7 }

  condition:
    any of them
}