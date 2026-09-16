rule TTP_XOR_QUAD_CurrentVersionRun_abf3 {
  strings:
    $key_abf3 = { f8 9c [2] dc 92 [2] f7 be [2] d9 9c [2] cd 87 [2] c2 9d [2] dc 80 [2] de 81 [2] c5 87 [2] d9 80 [2] c5 af }

  condition:
    any of them
}