rule TTP_XOR_QUAD_CurrentVersionRun_abcb {
  strings:
    $key_abcb = { f8 a4 [2] dc aa [2] f7 86 [2] d9 a4 [2] cd bf [2] c2 a5 [2] dc b8 [2] de b9 [2] c5 bf [2] d9 b8 [2] c5 97 }

  condition:
    any of them
}