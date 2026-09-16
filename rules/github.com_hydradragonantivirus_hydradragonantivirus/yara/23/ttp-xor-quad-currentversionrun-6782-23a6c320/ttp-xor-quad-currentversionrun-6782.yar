rule TTP_XOR_QUAD_CurrentVersionRun_6782 {
  strings:
    $key_6782 = { 34 ed [2] 10 e3 [2] 3b cf [2] 15 ed [2] 01 f6 [2] 0e ec [2] 10 f1 [2] 12 f0 [2] 09 f6 [2] 15 f1 [2] 09 de }

  condition:
    any of them
}