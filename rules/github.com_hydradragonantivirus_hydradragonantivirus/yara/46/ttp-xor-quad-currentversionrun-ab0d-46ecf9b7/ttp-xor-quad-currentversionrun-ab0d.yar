rule TTP_XOR_QUAD_CurrentVersionRun_ab0d {
  strings:
    $key_ab0d = { f8 62 [2] dc 6c [2] f7 40 [2] d9 62 [2] cd 79 [2] c2 63 [2] dc 7e [2] de 7f [2] c5 79 [2] d9 7e [2] c5 51 }

  condition:
    any of them
}