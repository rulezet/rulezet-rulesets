rule TTP_XOR_QUAD_CurrentVersionRun_a9b4 {
  strings:
    $key_a9b4 = { fa db [2] de d5 [2] f5 f9 [2] db db [2] cf c0 [2] c0 da [2] de c7 [2] dc c6 [2] c7 c0 [2] db c7 [2] c7 e8 }

  condition:
    any of them
}