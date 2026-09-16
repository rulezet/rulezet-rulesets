rule TTP_XOR_QUAD_CurrentVersionRun_d682 {
  strings:
    $key_d682 = { 85 ed [2] a1 e3 [2] 8a cf [2] a4 ed [2] b0 f6 [2] bf ec [2] a1 f1 [2] a3 f0 [2] b8 f6 [2] a4 f1 [2] b8 de }

  condition:
    any of them
}