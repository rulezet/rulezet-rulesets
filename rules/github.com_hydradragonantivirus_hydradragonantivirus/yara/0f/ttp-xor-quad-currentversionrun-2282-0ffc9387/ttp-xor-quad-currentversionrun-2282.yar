rule TTP_XOR_QUAD_CurrentVersionRun_2282 {
  strings:
    $key_2282 = { 71 ed [2] 55 e3 [2] 7e cf [2] 50 ed [2] 44 f6 [2] 4b ec [2] 55 f1 [2] 57 f0 [2] 4c f6 [2] 50 f1 [2] 4c de }

  condition:
    any of them
}