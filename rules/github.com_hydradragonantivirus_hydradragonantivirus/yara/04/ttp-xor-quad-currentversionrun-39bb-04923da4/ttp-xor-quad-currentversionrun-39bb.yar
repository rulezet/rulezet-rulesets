rule TTP_XOR_QUAD_CurrentVersionRun_39bb {
  strings:
    $key_39bb = { 6a d4 [2] 4e da [2] 65 f6 [2] 4b d4 [2] 5f cf [2] 50 d5 [2] 4e c8 [2] 4c c9 [2] 57 cf [2] 4b c8 [2] 57 e7 }

  condition:
    any of them
}