rule TTP_XOR_QUAD_CurrentVersionRun_6dbb {
  strings:
    $key_6dbb = { 3e d4 [2] 1a da [2] 31 f6 [2] 1f d4 [2] 0b cf [2] 04 d5 [2] 1a c8 [2] 18 c9 [2] 03 cf [2] 1f c8 [2] 03 e7 }

  condition:
    any of them
}