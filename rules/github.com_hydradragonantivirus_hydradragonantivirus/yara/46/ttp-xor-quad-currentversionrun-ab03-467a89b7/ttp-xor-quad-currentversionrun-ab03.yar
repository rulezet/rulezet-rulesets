rule TTP_XOR_QUAD_CurrentVersionRun_ab03 {
  strings:
    $key_ab03 = { f8 6c [2] dc 62 [2] f7 4e [2] d9 6c [2] cd 77 [2] c2 6d [2] dc 70 [2] de 71 [2] c5 77 [2] d9 70 [2] c5 5f }

  condition:
    any of them
}