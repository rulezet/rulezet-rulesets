rule TTP_XOR_QUAD_CurrentVersionRun_49bb {
  strings:
    $key_49bb = { 1a d4 [2] 3e da [2] 15 f6 [2] 3b d4 [2] 2f cf [2] 20 d5 [2] 3e c8 [2] 3c c9 [2] 27 cf [2] 3b c8 [2] 27 e7 }

  condition:
    any of them
}