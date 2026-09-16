rule TTP_XOR_QUAD_CurrentVersionRun_ab3e {
  strings:
    $key_ab3e = { f8 51 [2] dc 5f [2] f7 73 [2] d9 51 [2] cd 4a [2] c2 50 [2] dc 4d [2] de 4c [2] c5 4a [2] d9 4d [2] c5 62 }

  condition:
    any of them
}