rule TTP_XOR_QUAD_CurrentVersionRun_7abb {
  strings:
    $key_7abb = { 29 d4 [2] 0d da [2] 26 f6 [2] 08 d4 [2] 1c cf [2] 13 d5 [2] 0d c8 [2] 0f c9 [2] 14 cf [2] 08 c8 [2] 14 e7 }

  condition:
    any of them
}