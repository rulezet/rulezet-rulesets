rule TTP_XOR_QUAD_CurrentVersionRun_abd2 {
  strings:
    $key_abd2 = { f8 bd [2] dc b3 [2] f7 9f [2] d9 bd [2] cd a6 [2] c2 bc [2] dc a1 [2] de a0 [2] c5 a6 [2] d9 a1 [2] c5 8e }

  condition:
    any of them
}