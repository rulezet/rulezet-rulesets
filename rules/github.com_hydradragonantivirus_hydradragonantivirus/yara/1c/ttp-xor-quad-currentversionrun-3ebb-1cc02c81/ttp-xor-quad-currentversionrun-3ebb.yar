rule TTP_XOR_QUAD_CurrentVersionRun_3ebb {
  strings:
    $key_3ebb = { 6d d4 [2] 49 da [2] 62 f6 [2] 4c d4 [2] 58 cf [2] 57 d5 [2] 49 c8 [2] 4b c9 [2] 50 cf [2] 4c c8 [2] 50 e7 }

  condition:
    any of them
}