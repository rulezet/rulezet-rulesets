rule TTP_XOR_QUAD_CurrentVersionRun_a9b5 {
  strings:
    $key_a9b5 = { fa da [2] de d4 [2] f5 f8 [2] db da [2] cf c1 [2] c0 db [2] de c6 [2] dc c7 [2] c7 c1 [2] db c6 [2] c7 e9 }

  condition:
    any of them
}