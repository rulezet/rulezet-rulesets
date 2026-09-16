rule TTP_XOR_QUAD_CurrentVersionRun_abe5 {
  strings:
    $key_abe5 = { f8 8a [2] dc 84 [2] f7 a8 [2] d9 8a [2] cd 91 [2] c2 8b [2] dc 96 [2] de 97 [2] c5 91 [2] d9 96 [2] c5 b9 }

  condition:
    any of them
}