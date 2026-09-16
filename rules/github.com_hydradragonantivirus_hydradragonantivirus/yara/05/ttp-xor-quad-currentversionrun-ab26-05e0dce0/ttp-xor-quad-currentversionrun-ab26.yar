rule TTP_XOR_QUAD_CurrentVersionRun_ab26 {
  strings:
    $key_ab26 = { f8 49 [2] dc 47 [2] f7 6b [2] d9 49 [2] cd 52 [2] c2 48 [2] dc 55 [2] de 54 [2] c5 52 [2] d9 55 [2] c5 7a }

  condition:
    any of them
}