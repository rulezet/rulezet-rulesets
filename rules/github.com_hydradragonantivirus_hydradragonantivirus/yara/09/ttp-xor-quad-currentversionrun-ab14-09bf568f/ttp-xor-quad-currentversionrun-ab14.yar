rule TTP_XOR_QUAD_CurrentVersionRun_ab14 {
  strings:
    $key_ab14 = { f8 7b [2] dc 75 [2] f7 59 [2] d9 7b [2] cd 60 [2] c2 7a [2] dc 67 [2] de 66 [2] c5 60 [2] d9 67 [2] c5 48 }

  condition:
    any of them
}