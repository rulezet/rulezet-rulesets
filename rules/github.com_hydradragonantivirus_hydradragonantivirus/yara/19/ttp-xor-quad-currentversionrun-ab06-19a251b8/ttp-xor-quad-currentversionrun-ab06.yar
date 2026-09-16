rule TTP_XOR_QUAD_CurrentVersionRun_ab06 {
  strings:
    $key_ab06 = { f8 69 [2] dc 67 [2] f7 4b [2] d9 69 [2] cd 72 [2] c2 68 [2] dc 75 [2] de 74 [2] c5 72 [2] d9 75 [2] c5 5a }

  condition:
    any of them
}