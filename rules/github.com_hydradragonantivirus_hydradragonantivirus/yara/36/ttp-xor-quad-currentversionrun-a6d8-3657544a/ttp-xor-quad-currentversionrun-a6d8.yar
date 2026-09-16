rule TTP_XOR_QUAD_CurrentVersionRun_a6d8 {
  strings:
    $key_a6d8 = { f5 b7 [2] d1 b9 [2] fa 95 [2] d4 b7 [2] c0 ac [2] cf b6 [2] d1 ab [2] d3 aa [2] c8 ac [2] d4 ab [2] c8 84 }

  condition:
    any of them
}