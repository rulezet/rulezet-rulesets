rule TTP_XOR_QUAD_CurrentVersionRun_ab0e {
  strings:
    $key_ab0e = { f8 61 [2] dc 6f [2] f7 43 [2] d9 61 [2] cd 7a [2] c2 60 [2] dc 7d [2] de 7c [2] c5 7a [2] d9 7d [2] c5 52 }

  condition:
    any of them
}