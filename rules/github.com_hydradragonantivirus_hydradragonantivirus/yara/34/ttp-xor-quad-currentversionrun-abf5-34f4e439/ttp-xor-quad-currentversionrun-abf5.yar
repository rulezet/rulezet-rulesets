rule TTP_XOR_QUAD_CurrentVersionRun_abf5 {
  strings:
    $key_abf5 = { f8 9a [2] dc 94 [2] f7 b8 [2] d9 9a [2] cd 81 [2] c2 9b [2] dc 86 [2] de 87 [2] c5 81 [2] d9 86 [2] c5 a9 }

  condition:
    any of them
}