rule TTP_XOR_QUAD_CurrentVersionRun_abb7 {
  strings:
    $key_abb7 = { f8 d8 [2] dc d6 [2] f7 fa [2] d9 d8 [2] cd c3 [2] c2 d9 [2] dc c4 [2] de c5 [2] c5 c3 [2] d9 c4 [2] c5 eb }

  condition:
    any of them
}