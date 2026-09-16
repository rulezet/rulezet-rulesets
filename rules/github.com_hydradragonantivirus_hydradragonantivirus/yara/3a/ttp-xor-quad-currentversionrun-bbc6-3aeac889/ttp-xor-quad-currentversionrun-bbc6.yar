rule TTP_XOR_QUAD_CurrentVersionRun_bbc6 {
  strings:
    $key_bbc6 = { e8 a9 [2] cc a7 [2] e7 8b [2] c9 a9 [2] dd b2 [2] d2 a8 [2] cc b5 [2] ce b4 [2] d5 b2 [2] c9 b5 [2] d5 9a }

  condition:
    any of them
}