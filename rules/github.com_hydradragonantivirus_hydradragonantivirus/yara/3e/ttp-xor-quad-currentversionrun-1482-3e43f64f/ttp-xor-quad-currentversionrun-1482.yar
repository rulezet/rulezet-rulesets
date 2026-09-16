rule TTP_XOR_QUAD_CurrentVersionRun_1482 {
  strings:
    $key_1482 = { 47 ed [2] 63 e3 [2] 48 cf [2] 66 ed [2] 72 f6 [2] 7d ec [2] 63 f1 [2] 61 f0 [2] 7a f6 [2] 66 f1 [2] 7a de }

  condition:
    any of them
}