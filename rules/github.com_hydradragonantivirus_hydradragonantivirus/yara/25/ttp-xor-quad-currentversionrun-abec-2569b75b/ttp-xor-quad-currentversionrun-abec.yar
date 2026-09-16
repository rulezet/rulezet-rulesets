rule TTP_XOR_QUAD_CurrentVersionRun_abec {
  strings:
    $key_abec = { f8 83 [2] dc 8d [2] f7 a1 [2] d9 83 [2] cd 98 [2] c2 82 [2] dc 9f [2] de 9e [2] c5 98 [2] d9 9f [2] c5 b0 }

  condition:
    any of them
}