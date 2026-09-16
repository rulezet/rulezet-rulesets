rule TTP_XOR_QUAD_CurrentVersionRun_4682 {
  strings:
    $key_4682 = { 15 ed [2] 31 e3 [2] 1a cf [2] 34 ed [2] 20 f6 [2] 2f ec [2] 31 f1 [2] 33 f0 [2] 28 f6 [2] 34 f1 [2] 28 de }

  condition:
    any of them
}