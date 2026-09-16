rule TTP_XOR_QUAD_CurrentVersionRun_a9c7 {
  strings:
    $key_a9c7 = { fa a8 [2] de a6 [2] f5 8a [2] db a8 [2] cf b3 [2] c0 a9 [2] de b4 [2] dc b5 [2] c7 b3 [2] db b4 [2] c7 9b }

  condition:
    any of them
}