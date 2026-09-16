rule TTP_XOR_QUAD_CurrentVersionRun_c782 {
  strings:
    $key_c782 = { 94 ed [2] b0 e3 [2] 9b cf [2] b5 ed [2] a1 f6 [2] ae ec [2] b0 f1 [2] b2 f0 [2] a9 f6 [2] b5 f1 [2] a9 de }

  condition:
    any of them
}