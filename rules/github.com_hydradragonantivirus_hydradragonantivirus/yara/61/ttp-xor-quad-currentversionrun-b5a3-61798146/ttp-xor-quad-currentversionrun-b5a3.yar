rule TTP_XOR_QUAD_CurrentVersionRun_b5a3 {
  strings:
    $key_b5a3 = { e6 cc [2] c2 c2 [2] e9 ee [2] c7 cc [2] d3 d7 [2] dc cd [2] c2 d0 [2] c0 d1 [2] db d7 [2] c7 d0 [2] db ff }

  condition:
    any of them
}