rule TTP_XOR_QUAD_CurrentVersionRun_aaa7 {
  strings:
    $key_aaa7 = { f9 c8 [2] dd c6 [2] f6 ea [2] d8 c8 [2] cc d3 [2] c3 c9 [2] dd d4 [2] df d5 [2] c4 d3 [2] d8 d4 [2] c4 fb }

  condition:
    any of them
}