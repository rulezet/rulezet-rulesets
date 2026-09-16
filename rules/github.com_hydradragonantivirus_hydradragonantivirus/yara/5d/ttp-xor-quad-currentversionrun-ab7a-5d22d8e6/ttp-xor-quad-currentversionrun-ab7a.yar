rule TTP_XOR_QUAD_CurrentVersionRun_ab7a {
  strings:
    $key_ab7a = { f8 15 [2] dc 1b [2] f7 37 [2] d9 15 [2] cd 0e [2] c2 14 [2] dc 09 [2] de 08 [2] c5 0e [2] d9 09 [2] c5 26 }

  condition:
    any of them
}