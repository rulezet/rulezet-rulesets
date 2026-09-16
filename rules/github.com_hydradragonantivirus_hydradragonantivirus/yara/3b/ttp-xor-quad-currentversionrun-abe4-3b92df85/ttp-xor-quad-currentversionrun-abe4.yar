rule TTP_XOR_QUAD_CurrentVersionRun_abe4 {
  strings:
    $key_abe4 = { f8 8b [2] dc 85 [2] f7 a9 [2] d9 8b [2] cd 90 [2] c2 8a [2] dc 97 [2] de 96 [2] c5 90 [2] d9 97 [2] c5 b8 }

  condition:
    any of them
}