rule TTP_XOR_QUAD_CurrentVersionRun_a48e {
  strings:
    $key_a48e = { f7 e1 [2] d3 ef [2] f8 c3 [2] d6 e1 [2] c2 fa [2] cd e0 [2] d3 fd [2] d1 fc [2] ca fa [2] d6 fd [2] ca d2 }

  condition:
    any of them
}