rule TTP_XOR_QUAD_CurrentVersionRun_ab4a {
  strings:
    $key_ab4a = { f8 25 [2] dc 2b [2] f7 07 [2] d9 25 [2] cd 3e [2] c2 24 [2] dc 39 [2] de 38 [2] c5 3e [2] d9 39 [2] c5 16 }

  condition:
    any of them
}