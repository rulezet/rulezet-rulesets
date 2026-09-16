rule TTP_XOR_QUAD_CurrentVersionRun_a4b6 {
  strings:
    $key_a4b6 = { f7 d9 [2] d3 d7 [2] f8 fb [2] d6 d9 [2] c2 c2 [2] cd d8 [2] d3 c5 [2] d1 c4 [2] ca c2 [2] d6 c5 [2] ca ea }

  condition:
    any of them
}