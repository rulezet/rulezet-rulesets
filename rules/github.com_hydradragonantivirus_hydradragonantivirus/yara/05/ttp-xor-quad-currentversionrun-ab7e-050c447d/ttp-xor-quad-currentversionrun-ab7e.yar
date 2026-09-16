rule TTP_XOR_QUAD_CurrentVersionRun_ab7e {
  strings:
    $key_ab7e = { f8 11 [2] dc 1f [2] f7 33 [2] d9 11 [2] cd 0a [2] c2 10 [2] dc 0d [2] de 0c [2] c5 0a [2] d9 0d [2] c5 22 }

  condition:
    any of them
}