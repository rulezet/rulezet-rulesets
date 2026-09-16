rule TTP_XOR_QUAD_CurrentVersionRun_b2df {
  strings:
    $key_b2df = { e1 b0 [2] c5 be [2] ee 92 [2] c0 b0 [2] d4 ab [2] db b1 [2] c5 ac [2] c7 ad [2] dc ab [2] c0 ac [2] dc 83 }

  condition:
    any of them
}