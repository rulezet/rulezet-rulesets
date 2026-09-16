rule TTP_XOR_QUAD_CurrentVersionRun_a49b {
  strings:
    $key_a49b = { f7 f4 [2] d3 fa [2] f8 d6 [2] d6 f4 [2] c2 ef [2] cd f5 [2] d3 e8 [2] d1 e9 [2] ca ef [2] d6 e8 [2] ca c7 }

  condition:
    any of them
}