rule TTP_XOR_QUAD_CurrentVersionRun_ab11 {
  strings:
    $key_ab11 = { f8 7e [2] dc 70 [2] f7 5c [2] d9 7e [2] cd 65 [2] c2 7f [2] dc 62 [2] de 63 [2] c5 65 [2] d9 62 [2] c5 4d }

  condition:
    any of them
}