rule TTP_XOR_QUAD_CurrentVersionRun_ab7d {
  strings:
    $key_ab7d = { f8 12 [2] dc 1c [2] f7 30 [2] d9 12 [2] cd 09 [2] c2 13 [2] dc 0e [2] de 0f [2] c5 09 [2] d9 0e [2] c5 21 }

  condition:
    any of them
}