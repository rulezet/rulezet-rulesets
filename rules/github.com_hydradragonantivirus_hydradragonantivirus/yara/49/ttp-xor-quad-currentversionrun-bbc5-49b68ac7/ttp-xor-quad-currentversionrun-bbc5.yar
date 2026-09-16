rule TTP_XOR_QUAD_CurrentVersionRun_bbc5 {
  strings:
    $key_bbc5 = { e8 aa [2] cc a4 [2] e7 88 [2] c9 aa [2] dd b1 [2] d2 ab [2] cc b6 [2] ce b7 [2] d5 b1 [2] c9 b6 [2] d5 99 }

  condition:
    any of them
}