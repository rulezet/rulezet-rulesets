rule TTP_XOR_QUAD_CurrentVersionRun_acd5 {
  strings:
    $key_acd5 = { ff ba [2] db b4 [2] f0 98 [2] de ba [2] ca a1 [2] c5 bb [2] db a6 [2] d9 a7 [2] c2 a1 [2] de a6 [2] c2 89 }

  condition:
    any of them
}