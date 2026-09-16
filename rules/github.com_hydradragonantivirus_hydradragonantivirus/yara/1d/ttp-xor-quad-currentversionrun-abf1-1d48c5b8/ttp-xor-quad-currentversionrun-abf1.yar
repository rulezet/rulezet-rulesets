rule TTP_XOR_QUAD_CurrentVersionRun_abf1 {
  strings:
    $key_abf1 = { f8 9e [2] dc 90 [2] f7 bc [2] d9 9e [2] cd 85 [2] c2 9f [2] dc 82 [2] de 83 [2] c5 85 [2] d9 82 [2] c5 ad }

  condition:
    any of them
}