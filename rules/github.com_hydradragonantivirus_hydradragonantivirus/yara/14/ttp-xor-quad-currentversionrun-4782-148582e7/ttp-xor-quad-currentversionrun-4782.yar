rule TTP_XOR_QUAD_CurrentVersionRun_4782 {
  strings:
    $key_4782 = { 14 ed [2] 30 e3 [2] 1b cf [2] 35 ed [2] 21 f6 [2] 2e ec [2] 30 f1 [2] 32 f0 [2] 29 f6 [2] 35 f1 [2] 29 de }

  condition:
    any of them
}