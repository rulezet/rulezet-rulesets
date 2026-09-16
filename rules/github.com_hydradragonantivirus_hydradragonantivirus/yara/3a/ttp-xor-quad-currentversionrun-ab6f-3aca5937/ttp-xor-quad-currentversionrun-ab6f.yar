rule TTP_XOR_QUAD_CurrentVersionRun_ab6f {
  strings:
    $key_ab6f = { f8 00 [2] dc 0e [2] f7 22 [2] d9 00 [2] cd 1b [2] c2 01 [2] dc 1c [2] de 1d [2] c5 1b [2] d9 1c [2] c5 33 }

  condition:
    any of them
}