rule TTP_XOR_QUAD_CurrentVersionRun_3782 {
  strings:
    $key_3782 = { 64 ed [2] 40 e3 [2] 6b cf [2] 45 ed [2] 51 f6 [2] 5e ec [2] 40 f1 [2] 42 f0 [2] 59 f6 [2] 45 f1 [2] 59 de }

  condition:
    any of them
}