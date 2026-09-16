rule TTP_XOR_QUAD_CurrentVersionRun_b2d3 {
  strings:
    $key_b2d3 = { e1 bc [2] c5 b2 [2] ee 9e [2] c0 bc [2] d4 a7 [2] db bd [2] c5 a0 [2] c7 a1 [2] dc a7 [2] c0 a0 [2] dc 8f }

  condition:
    any of them
}