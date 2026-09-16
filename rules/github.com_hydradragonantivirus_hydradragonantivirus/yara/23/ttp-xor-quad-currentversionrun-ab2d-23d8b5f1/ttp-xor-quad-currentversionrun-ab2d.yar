rule TTP_XOR_QUAD_CurrentVersionRun_ab2d {
  strings:
    $key_ab2d = { f8 42 [2] dc 4c [2] f7 60 [2] d9 42 [2] cd 59 [2] c2 43 [2] dc 5e [2] de 5f [2] c5 59 [2] d9 5e [2] c5 71 }

  condition:
    any of them
}