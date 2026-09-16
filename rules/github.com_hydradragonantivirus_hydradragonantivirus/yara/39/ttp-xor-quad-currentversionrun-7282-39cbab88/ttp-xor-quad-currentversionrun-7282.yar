rule TTP_XOR_QUAD_CurrentVersionRun_7282 {
  strings:
    $key_7282 = { 21 ed [2] 05 e3 [2] 2e cf [2] 00 ed [2] 14 f6 [2] 1b ec [2] 05 f1 [2] 07 f0 [2] 1c f6 [2] 00 f1 [2] 1c de }

  condition:
    any of them
}