rule TTP_XOR_QUAD_CurrentVersionRun_c5bb {
  strings:
    $key_c5bb = { 96 d4 [2] b2 da [2] 99 f6 [2] b7 d4 [2] a3 cf [2] ac d5 [2] b2 c8 [2] b0 c9 [2] ab cf [2] b7 c8 [2] ab e7 }

  condition:
    any of them
}