rule TTP_XOR_QUAD_CurrentVersionRun_ab48 {
  strings:
    $key_ab48 = { f8 27 [2] dc 29 [2] f7 05 [2] d9 27 [2] cd 3c [2] c2 26 [2] dc 3b [2] de 3a [2] c5 3c [2] d9 3b [2] c5 14 }

  condition:
    any of them
}