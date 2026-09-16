rule TTP_XOR_QUAD_CurrentVersionRun_ab6e {
  strings:
    $key_ab6e = { f8 01 [2] dc 0f [2] f7 23 [2] d9 01 [2] cd 1a [2] c2 00 [2] dc 1d [2] de 1c [2] c5 1a [2] d9 1d [2] c5 32 }

  condition:
    any of them
}