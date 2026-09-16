rule TTP_XOR_QUAD_CurrentVersionRun_5dbb {
  strings:
    $key_5dbb = { 0e d4 [2] 2a da [2] 01 f6 [2] 2f d4 [2] 3b cf [2] 34 d5 [2] 2a c8 [2] 28 c9 [2] 33 cf [2] 2f c8 [2] 33 e7 }

  condition:
    any of them
}