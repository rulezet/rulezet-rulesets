rule TTP_XOR_QUAD_CurrentVersionRun_f582 {
  strings:
    $key_f582 = { a6 ed [2] 82 e3 [2] a9 cf [2] 87 ed [2] 93 f6 [2] 9c ec [2] 82 f1 [2] 80 f0 [2] 9b f6 [2] 87 f1 [2] 9b de }

  condition:
    any of them
}