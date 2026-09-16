rule TTP_XOR_QUAD_CurrentVersionRun_a98f {
  strings:
    $key_a98f = { fa e0 [2] de ee [2] f5 c2 [2] db e0 [2] cf fb [2] c0 e1 [2] de fc [2] dc fd [2] c7 fb [2] db fc [2] c7 d3 }

  condition:
    any of them
}