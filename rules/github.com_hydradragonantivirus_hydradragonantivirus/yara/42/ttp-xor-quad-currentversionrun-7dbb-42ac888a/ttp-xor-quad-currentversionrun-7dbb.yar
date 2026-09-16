rule TTP_XOR_QUAD_CurrentVersionRun_7dbb {
  strings:
    $key_7dbb = { 2e d4 [2] 0a da [2] 21 f6 [2] 0f d4 [2] 1b cf [2] 14 d5 [2] 0a c8 [2] 08 c9 [2] 13 cf [2] 0f c8 [2] 13 e7 }

  condition:
    any of them
}