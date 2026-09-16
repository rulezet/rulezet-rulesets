rule TTP_XOR_QUAD_CurrentVersionRun_5482 {
  strings:
    $key_5482 = { 07 ed [2] 23 e3 [2] 08 cf [2] 26 ed [2] 32 f6 [2] 3d ec [2] 23 f1 [2] 21 f0 [2] 3a f6 [2] 26 f1 [2] 3a de }

  condition:
    any of them
}