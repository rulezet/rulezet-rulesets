rule TTP_XOR_QUAD_CurrentVersionRun_3abb {
  strings:
    $key_3abb = { 69 d4 [2] 4d da [2] 66 f6 [2] 48 d4 [2] 5c cf [2] 53 d5 [2] 4d c8 [2] 4f c9 [2] 54 cf [2] 48 c8 [2] 54 e7 }

  condition:
    any of them
}