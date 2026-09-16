rule TTP_XOR_QUAD_CurrentVersionRun_ab6c {
  strings:
    $key_ab6c = { f8 03 [2] dc 0d [2] f7 21 [2] d9 03 [2] cd 18 [2] c2 02 [2] dc 1f [2] de 1e [2] c5 18 [2] d9 1f [2] c5 30 }

  condition:
    any of them
}