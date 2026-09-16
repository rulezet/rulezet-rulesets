rule TTP_XOR_QUAD_CurrentVersionRun_ac8f {
  strings:
    $key_ac8f = { ff e0 [2] db ee [2] f0 c2 [2] de e0 [2] ca fb [2] c5 e1 [2] db fc [2] d9 fd [2] c2 fb [2] de fc [2] c2 d3 }

  condition:
    any of them
}