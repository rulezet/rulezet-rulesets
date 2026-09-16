rule TTP_XOR_QUAD_CurrentVersionRun_9fd4 {
  strings:
    $key_9fd4 = { cc bb [2] e8 b5 [2] c3 99 [2] ed bb [2] f9 a0 [2] f6 ba [2] e8 a7 [2] ea a6 [2] f1 a0 [2] ed a7 [2] f1 88 }

  condition:
    any of them
}