rule TTP_XOR_QUAD_CurrentVersionRun_2ebb {
  strings:
    $key_2ebb = { 7d d4 [2] 59 da [2] 72 f6 [2] 5c d4 [2] 48 cf [2] 47 d5 [2] 59 c8 [2] 5b c9 [2] 40 cf [2] 5c c8 [2] 40 e7 }

  condition:
    any of them
}