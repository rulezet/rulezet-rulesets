rule TTP_XOR_QUAD_CurrentVersionRun_9ec8 {
  strings:
    $key_9ec8 = { cd a7 [2] e9 a9 [2] c2 85 [2] ec a7 [2] f8 bc [2] f7 a6 [2] e9 bb [2] eb ba [2] f0 bc [2] ec bb [2] f0 94 }

  condition:
    any of them
}