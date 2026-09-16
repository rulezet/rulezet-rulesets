rule TTP_XOR_QUAD_CurrentVersionRun_a48f {
  strings:
    $key_a48f = { f7 e0 [2] d3 ee [2] f8 c2 [2] d6 e0 [2] c2 fb [2] cd e1 [2] d3 fc [2] d1 fd [2] ca fb [2] d6 fc [2] ca d3 }

  condition:
    any of them
}