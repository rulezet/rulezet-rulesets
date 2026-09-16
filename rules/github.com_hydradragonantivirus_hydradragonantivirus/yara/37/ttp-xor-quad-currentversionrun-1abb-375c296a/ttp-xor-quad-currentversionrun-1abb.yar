rule TTP_XOR_QUAD_CurrentVersionRun_1abb {
  strings:
    $key_1abb = { 49 d4 [2] 6d da [2] 46 f6 [2] 68 d4 [2] 7c cf [2] 73 d5 [2] 6d c8 [2] 6f c9 [2] 74 cf [2] 68 c8 [2] 74 e7 }

  condition:
    any of them
}