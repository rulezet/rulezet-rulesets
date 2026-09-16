rule TTP_XOR_QUAD_CurrentVersionRun_3682 {
  strings:
    $key_3682 = { 65 ed [2] 41 e3 [2] 6a cf [2] 44 ed [2] 50 f6 [2] 5f ec [2] 41 f1 [2] 43 f0 [2] 58 f6 [2] 44 f1 [2] 58 de }

  condition:
    any of them
}