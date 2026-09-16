rule TTP_XOR_QUAD_CurrentVersionRun_ab28 {
  strings:
    $key_ab28 = { f8 47 [2] dc 49 [2] f7 65 [2] d9 47 [2] cd 5c [2] c2 46 [2] dc 5b [2] de 5a [2] c5 5c [2] d9 5b [2] c5 74 }

  condition:
    any of them
}