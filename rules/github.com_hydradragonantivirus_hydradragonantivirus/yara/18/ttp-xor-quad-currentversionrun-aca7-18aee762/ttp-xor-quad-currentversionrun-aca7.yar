rule TTP_XOR_QUAD_CurrentVersionRun_aca7 {
  strings:
    $key_aca7 = { ff c8 [2] db c6 [2] f0 ea [2] de c8 [2] ca d3 [2] c5 c9 [2] db d4 [2] d9 d5 [2] c2 d3 [2] de d4 [2] c2 fb }

  condition:
    any of them
}