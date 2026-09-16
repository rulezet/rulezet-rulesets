rule TTP_XOR_QUAD_CurrentVersionRun_abc9 {
  strings:
    $key_abc9 = { f8 a6 [2] dc a8 [2] f7 84 [2] d9 a6 [2] cd bd [2] c2 a7 [2] dc ba [2] de bb [2] c5 bd [2] d9 ba [2] c5 95 }

  condition:
    any of them
}