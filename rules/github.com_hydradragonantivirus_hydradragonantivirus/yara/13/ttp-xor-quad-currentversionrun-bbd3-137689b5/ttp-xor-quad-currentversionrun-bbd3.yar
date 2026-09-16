rule TTP_XOR_QUAD_CurrentVersionRun_bbd3 {
  strings:
    $key_bbd3 = { e8 bc [2] cc b2 [2] e7 9e [2] c9 bc [2] dd a7 [2] d2 bd [2] cc a0 [2] ce a1 [2] d5 a7 [2] c9 a0 [2] d5 8f }

  condition:
    any of them
}