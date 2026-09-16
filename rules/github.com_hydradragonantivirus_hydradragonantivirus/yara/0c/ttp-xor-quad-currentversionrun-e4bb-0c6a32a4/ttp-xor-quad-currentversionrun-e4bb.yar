rule TTP_XOR_QUAD_CurrentVersionRun_e4bb {
  strings:
    $key_e4bb = { b7 d4 [2] 93 da [2] b8 f6 [2] 96 d4 [2] 82 cf [2] 8d d5 [2] 93 c8 [2] 91 c9 [2] 8a cf [2] 96 c8 [2] 8a e7 }

  condition:
    any of them
}