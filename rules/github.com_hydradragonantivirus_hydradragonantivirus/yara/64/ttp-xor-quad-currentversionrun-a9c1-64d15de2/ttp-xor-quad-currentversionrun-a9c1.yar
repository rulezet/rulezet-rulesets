rule TTP_XOR_QUAD_CurrentVersionRun_a9c1 {
  strings:
    $key_a9c1 = { fa ae [2] de a0 [2] f5 8c [2] db ae [2] cf b5 [2] c0 af [2] de b2 [2] dc b3 [2] c7 b5 [2] db b2 [2] c7 9d }

  condition:
    any of them
}