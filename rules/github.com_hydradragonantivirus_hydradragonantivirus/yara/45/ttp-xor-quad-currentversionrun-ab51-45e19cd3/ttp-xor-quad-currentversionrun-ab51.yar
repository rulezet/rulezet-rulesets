rule TTP_XOR_QUAD_CurrentVersionRun_ab51 {
  strings:
    $key_ab51 = { f8 3e [2] dc 30 [2] f7 1c [2] d9 3e [2] cd 25 [2] c2 3f [2] dc 22 [2] de 23 [2] c5 25 [2] d9 22 [2] c5 0d }

  condition:
    any of them
}