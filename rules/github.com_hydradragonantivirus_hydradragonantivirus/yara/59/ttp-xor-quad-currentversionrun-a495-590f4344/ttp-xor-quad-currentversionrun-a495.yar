rule TTP_XOR_QUAD_CurrentVersionRun_a495 {
  strings:
    $key_a495 = { f7 fa [2] d3 f4 [2] f8 d8 [2] d6 fa [2] c2 e1 [2] cd fb [2] d3 e6 [2] d1 e7 [2] ca e1 [2] d6 e6 [2] ca c9 }

  condition:
    any of them
}