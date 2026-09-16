rule TTP_XOR_QUAD_CurrentVersionRun_a780 {
  strings:
    $key_a780 = { f4 ef [2] d0 e1 [2] fb cd [2] d5 ef [2] c1 f4 [2] ce ee [2] d0 f3 [2] d2 f2 [2] c9 f4 [2] d5 f3 [2] c9 dc }

  condition:
    any of them
}