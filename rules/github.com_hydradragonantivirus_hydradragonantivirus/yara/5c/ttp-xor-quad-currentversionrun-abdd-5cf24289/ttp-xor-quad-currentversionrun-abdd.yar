rule TTP_XOR_QUAD_CurrentVersionRun_abdd {
  strings:
    $key_abdd = { f8 b2 [2] dc bc [2] f7 90 [2] d9 b2 [2] cd a9 [2] c2 b3 [2] dc ae [2] de af [2] c5 a9 [2] d9 ae [2] c5 81 }

  condition:
    any of them
}