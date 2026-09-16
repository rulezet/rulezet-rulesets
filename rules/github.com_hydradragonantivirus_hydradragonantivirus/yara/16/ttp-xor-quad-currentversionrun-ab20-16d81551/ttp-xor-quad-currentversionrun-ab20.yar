rule TTP_XOR_QUAD_CurrentVersionRun_ab20 {
  strings:
    $key_ab20 = { f8 4f [2] dc 41 [2] f7 6d [2] d9 4f [2] cd 54 [2] c2 4e [2] dc 53 [2] de 52 [2] c5 54 [2] d9 53 [2] c5 7c }

  condition:
    any of them
}