rule TTP_XOR_QUAD_CurrentVersionRun_abd4 {
  strings:
    $key_abd4 = { f8 bb [2] dc b5 [2] f7 99 [2] d9 bb [2] cd a0 [2] c2 ba [2] dc a7 [2] de a6 [2] c5 a0 [2] d9 a7 [2] c5 88 }

  condition:
    any of them
}