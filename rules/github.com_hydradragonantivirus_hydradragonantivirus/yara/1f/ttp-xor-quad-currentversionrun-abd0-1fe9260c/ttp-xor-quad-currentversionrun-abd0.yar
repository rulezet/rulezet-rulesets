rule TTP_XOR_QUAD_CurrentVersionRun_abd0 {
  strings:
    $key_abd0 = { f8 bf [2] dc b1 [2] f7 9d [2] d9 bf [2] cd a4 [2] c2 be [2] dc a3 [2] de a2 [2] c5 a4 [2] d9 a3 [2] c5 8c }

  condition:
    any of them
}