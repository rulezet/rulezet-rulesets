rule TTP_XOR_QUAD_CurrentVersionRun_6682 {
  strings:
    $key_6682 = { 35 ed [2] 11 e3 [2] 3a cf [2] 14 ed [2] 00 f6 [2] 0f ec [2] 11 f1 [2] 13 f0 [2] 08 f6 [2] 14 f1 [2] 08 de }

  condition:
    any of them
}