rule TTP_XOR_QUAD_CurrentVersionRun_bbc4 {
  strings:
    $key_bbc4 = { e8 ab [2] cc a5 [2] e7 89 [2] c9 ab [2] dd b0 [2] d2 aa [2] cc b7 [2] ce b6 [2] d5 b0 [2] c9 b7 [2] d5 98 }

  condition:
    any of them
}