rule TTP_XOR_QUAD_CurrentVersionRun_f2bb {
  strings:
    $key_f2bb = { a1 d4 [2] 85 da [2] ae f6 [2] 80 d4 [2] 94 cf [2] 9b d5 [2] 85 c8 [2] 87 c9 [2] 9c cf [2] 80 c8 [2] 9c e7 }

  condition:
    any of them
}