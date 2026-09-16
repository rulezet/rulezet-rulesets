rule TTP_XOR_QUAD_CurrentVersionRun_ab62 {
  strings:
    $key_ab62 = { f8 0d [2] dc 03 [2] f7 2f [2] d9 0d [2] cd 16 [2] c2 0c [2] dc 11 [2] de 10 [2] c5 16 [2] d9 11 [2] c5 3e }

  condition:
    any of them
}