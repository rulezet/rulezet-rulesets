rule TTP_XOR_QUAD_CurrentVersionRun_f9bb {
  strings:
    $key_f9bb = { aa d4 [2] 8e da [2] a5 f6 [2] 8b d4 [2] 9f cf [2] 90 d5 [2] 8e c8 [2] 8c c9 [2] 97 cf [2] 8b c8 [2] 97 e7 }

  condition:
    any of them
}