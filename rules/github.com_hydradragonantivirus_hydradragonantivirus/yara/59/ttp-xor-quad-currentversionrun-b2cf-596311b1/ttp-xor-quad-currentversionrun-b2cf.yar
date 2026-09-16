rule TTP_XOR_QUAD_CurrentVersionRun_b2cf {
  strings:
    $key_b2cf = { e1 a0 [2] c5 ae [2] ee 82 [2] c0 a0 [2] d4 bb [2] db a1 [2] c5 bc [2] c7 bd [2] dc bb [2] c0 bc [2] dc 93 }

  condition:
    any of them
}