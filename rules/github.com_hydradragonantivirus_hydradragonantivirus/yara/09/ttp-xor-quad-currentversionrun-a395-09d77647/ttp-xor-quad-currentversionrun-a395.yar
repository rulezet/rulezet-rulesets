rule TTP_XOR_QUAD_CurrentVersionRun_a395 {
  strings:
    $key_a395 = { f0 fa [2] d4 f4 [2] ff d8 [2] d1 fa [2] c5 e1 [2] ca fb [2] d4 e6 [2] d6 e7 [2] cd e1 [2] d1 e6 [2] cd c9 }

  condition:
    any of them
}