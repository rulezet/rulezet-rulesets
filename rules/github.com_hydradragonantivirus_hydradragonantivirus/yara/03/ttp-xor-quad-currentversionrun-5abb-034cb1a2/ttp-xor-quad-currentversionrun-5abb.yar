rule TTP_XOR_QUAD_CurrentVersionRun_5abb {
  strings:
    $key_5abb = { 09 d4 [2] 2d da [2] 06 f6 [2] 28 d4 [2] 3c cf [2] 33 d5 [2] 2d c8 [2] 2f c9 [2] 34 cf [2] 28 c8 [2] 34 e7 }

  condition:
    any of them
}