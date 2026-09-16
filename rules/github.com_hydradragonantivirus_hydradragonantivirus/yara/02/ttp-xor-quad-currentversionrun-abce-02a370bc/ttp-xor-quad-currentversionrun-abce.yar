rule TTP_XOR_QUAD_CurrentVersionRun_abce {
  strings:
    $key_abce = { f8 a1 [2] dc af [2] f7 83 [2] d9 a1 [2] cd ba [2] c2 a0 [2] dc bd [2] de bc [2] c5 ba [2] d9 bd [2] c5 92 }

  condition:
    any of them
}