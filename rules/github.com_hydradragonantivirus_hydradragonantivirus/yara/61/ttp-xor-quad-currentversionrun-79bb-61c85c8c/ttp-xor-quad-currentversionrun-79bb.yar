rule TTP_XOR_QUAD_CurrentVersionRun_79bb {
  strings:
    $key_79bb = { 2a d4 [2] 0e da [2] 25 f6 [2] 0b d4 [2] 1f cf [2] 10 d5 [2] 0e c8 [2] 0c c9 [2] 17 cf [2] 0b c8 [2] 17 e7 }

  condition:
    any of them
}