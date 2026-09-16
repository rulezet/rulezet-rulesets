rule TTP_XOR_QUAD_CurrentVersionRun_8ebb {
  strings:
    $key_8ebb = { dd d4 [2] f9 da [2] d2 f6 [2] fc d4 [2] e8 cf [2] e7 d5 [2] f9 c8 [2] fb c9 [2] e0 cf [2] fc c8 [2] e0 e7 }

  condition:
    any of them
}