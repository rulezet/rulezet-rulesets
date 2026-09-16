rule TTP_XOR_QUAD_CurrentVersionRun_6482 {
  strings:
    $key_6482 = { 37 ed [2] 13 e3 [2] 38 cf [2] 16 ed [2] 02 f6 [2] 0d ec [2] 13 f1 [2] 11 f0 [2] 0a f6 [2] 16 f1 [2] 0a de }

  condition:
    any of them
}