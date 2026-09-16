rule TTP_XOR_QUAD_CurrentVersionRun_a9c6 {
  strings:
    $key_a9c6 = { fa a9 [2] de a7 [2] f5 8b [2] db a9 [2] cf b2 [2] c0 a8 [2] de b5 [2] dc b4 [2] c7 b2 [2] db b5 [2] c7 9a }

  condition:
    any of them
}