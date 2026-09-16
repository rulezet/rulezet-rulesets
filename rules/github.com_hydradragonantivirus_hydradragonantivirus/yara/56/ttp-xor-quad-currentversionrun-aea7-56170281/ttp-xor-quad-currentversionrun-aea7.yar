rule TTP_XOR_QUAD_CurrentVersionRun_aea7 {
  strings:
    $key_aea7 = { fd c8 [2] d9 c6 [2] f2 ea [2] dc c8 [2] c8 d3 [2] c7 c9 [2] d9 d4 [2] db d5 [2] c0 d3 [2] dc d4 [2] c0 fb }

  condition:
    any of them
}