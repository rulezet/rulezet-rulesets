rule TTP_XOR_QUAD_CurrentVersionRun_ab6a {
  strings:
    $key_ab6a = { f8 05 [2] dc 0b [2] f7 27 [2] d9 05 [2] cd 1e [2] c2 04 [2] dc 19 [2] de 18 [2] c5 1e [2] d9 19 [2] c5 36 }

  condition:
    any of them
}