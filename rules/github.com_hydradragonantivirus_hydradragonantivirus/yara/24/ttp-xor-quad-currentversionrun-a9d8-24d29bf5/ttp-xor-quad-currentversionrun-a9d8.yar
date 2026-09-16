rule TTP_XOR_QUAD_CurrentVersionRun_a9d8 {
  strings:
    $key_a9d8 = { fa b7 [2] de b9 [2] f5 95 [2] db b7 [2] cf ac [2] c0 b6 [2] de ab [2] dc aa [2] c7 ac [2] db ab [2] c7 84 }

  condition:
    any of them
}