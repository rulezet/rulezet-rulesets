rule TTP_XOR_QUAD_CurrentVersionRun_a9cf {
  strings:
    $key_a9cf = { fa a0 [2] de ae [2] f5 82 [2] db a0 [2] cf bb [2] c0 a1 [2] de bc [2] dc bd [2] c7 bb [2] db bc [2] c7 93 }

  condition:
    any of them
}