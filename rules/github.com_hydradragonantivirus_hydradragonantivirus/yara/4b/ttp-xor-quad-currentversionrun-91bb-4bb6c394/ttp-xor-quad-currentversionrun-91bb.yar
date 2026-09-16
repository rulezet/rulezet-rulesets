rule TTP_XOR_QUAD_CurrentVersionRun_91bb {
  strings:
    $key_91bb = { c2 d4 [2] e6 da [2] cd f6 [2] e3 d4 [2] f7 cf [2] f8 d5 [2] e6 c8 [2] e4 c9 [2] ff cf [2] e3 c8 [2] ff e7 }

  condition:
    any of them
}