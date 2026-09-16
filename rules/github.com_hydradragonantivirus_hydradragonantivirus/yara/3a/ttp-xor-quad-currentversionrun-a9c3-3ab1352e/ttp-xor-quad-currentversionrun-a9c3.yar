rule TTP_XOR_QUAD_CurrentVersionRun_a9c3 {
  strings:
    $key_a9c3 = { fa ac [2] de a2 [2] f5 8e [2] db ac [2] cf b7 [2] c0 ad [2] de b0 [2] dc b1 [2] c7 b7 [2] db b0 [2] c7 9f }

  condition:
    any of them
}