rule TTP_XOR_QUAD_CurrentVersionRun_88bb {
  strings:
    $key_88bb = { db d4 [2] ff da [2] d4 f6 [2] fa d4 [2] ee cf [2] e1 d5 [2] ff c8 [2] fd c9 [2] e6 cf [2] fa c8 [2] e6 e7 }

  condition:
    any of them
}