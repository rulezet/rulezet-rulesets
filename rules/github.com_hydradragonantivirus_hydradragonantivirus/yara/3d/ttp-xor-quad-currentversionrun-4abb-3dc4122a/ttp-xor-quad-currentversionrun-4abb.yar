rule TTP_XOR_QUAD_CurrentVersionRun_4abb {
  strings:
    $key_4abb = { 19 d4 [2] 3d da [2] 16 f6 [2] 38 d4 [2] 2c cf [2] 23 d5 [2] 3d c8 [2] 3f c9 [2] 24 cf [2] 38 c8 [2] 24 e7 }

  condition:
    any of them
}