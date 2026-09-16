rule TTP_XOR_QUAD_CurrentVersionRun_ab7b {
  strings:
    $key_ab7b = { f8 14 [2] dc 1a [2] f7 36 [2] d9 14 [2] cd 0f [2] c2 15 [2] dc 08 [2] de 09 [2] c5 0f [2] d9 08 [2] c5 27 }

  condition:
    any of them
}