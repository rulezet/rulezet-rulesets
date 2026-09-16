rule TTP_XOR_QUAD_CurrentVersionRun_e6bb {
  strings:
    $key_e6bb = { b5 d4 [2] 91 da [2] ba f6 [2] 94 d4 [2] 80 cf [2] 8f d5 [2] 91 c8 [2] 93 c9 [2] 88 cf [2] 94 c8 [2] 88 e7 }

  condition:
    any of them
}