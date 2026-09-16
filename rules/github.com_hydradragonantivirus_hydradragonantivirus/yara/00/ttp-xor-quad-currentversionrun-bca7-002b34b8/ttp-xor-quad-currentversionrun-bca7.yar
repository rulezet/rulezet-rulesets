rule TTP_XOR_QUAD_CurrentVersionRun_bca7 {
  strings:
    $key_bca7 = { ef c8 [2] cb c6 [2] e0 ea [2] ce c8 [2] da d3 [2] d5 c9 [2] cb d4 [2] c9 d5 [2] d2 d3 [2] ce d4 [2] d2 fb }

  condition:
    any of them
}