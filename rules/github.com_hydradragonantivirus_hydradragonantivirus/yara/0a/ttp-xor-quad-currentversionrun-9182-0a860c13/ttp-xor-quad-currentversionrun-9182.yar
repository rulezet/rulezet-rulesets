rule TTP_XOR_QUAD_CurrentVersionRun_9182 {
  strings:
    $key_9182 = { c2 ed [2] e6 e3 [2] cd cf [2] e3 ed [2] f7 f6 [2] f8 ec [2] e6 f1 [2] e4 f0 [2] ff f6 [2] e3 f1 [2] ff de }

  condition:
    any of them
}