rule TTP_XOR_QUAD_CurrentVersionRun_6282 {
  strings:
    $key_6282 = { 31 ed [2] 15 e3 [2] 3e cf [2] 10 ed [2] 04 f6 [2] 0b ec [2] 15 f1 [2] 17 f0 [2] 0c f6 [2] 10 f1 [2] 0c de }

  condition:
    any of them
}