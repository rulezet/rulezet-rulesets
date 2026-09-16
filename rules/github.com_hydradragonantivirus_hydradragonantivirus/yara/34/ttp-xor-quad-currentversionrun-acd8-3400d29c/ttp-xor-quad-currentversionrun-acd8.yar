rule TTP_XOR_QUAD_CurrentVersionRun_acd8 {
  strings:
    $key_acd8 = { ff b7 [2] db b9 [2] f0 95 [2] de b7 [2] ca ac [2] c5 b6 [2] db ab [2] d9 aa [2] c2 ac [2] de ab [2] c2 84 }

  condition:
    any of them
}