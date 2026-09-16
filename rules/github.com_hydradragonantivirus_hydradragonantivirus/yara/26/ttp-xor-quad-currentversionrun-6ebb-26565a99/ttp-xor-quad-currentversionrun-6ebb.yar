rule TTP_XOR_QUAD_CurrentVersionRun_6ebb {
  strings:
    $key_6ebb = { 3d d4 [2] 19 da [2] 32 f6 [2] 1c d4 [2] 08 cf [2] 07 d5 [2] 19 c8 [2] 1b c9 [2] 00 cf [2] 1c c8 [2] 00 e7 }

  condition:
    any of them
}