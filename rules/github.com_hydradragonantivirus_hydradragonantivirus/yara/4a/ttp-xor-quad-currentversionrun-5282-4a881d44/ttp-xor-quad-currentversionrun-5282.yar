rule TTP_XOR_QUAD_CurrentVersionRun_5282 {
  strings:
    $key_5282 = { 01 ed [2] 25 e3 [2] 0e cf [2] 20 ed [2] 34 f6 [2] 3b ec [2] 25 f1 [2] 27 f0 [2] 3c f6 [2] 20 f1 [2] 3c de }

  condition:
    any of them
}