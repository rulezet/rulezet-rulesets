rule TTP_XOR_QUAD_CurrentVersionRun_a9d4 {
  strings:
    $key_a9d4 = { fa bb [2] de b5 [2] f5 99 [2] db bb [2] cf a0 [2] c0 ba [2] de a7 [2] dc a6 [2] c7 a0 [2] db a7 [2] c7 88 }

  condition:
    any of them
}