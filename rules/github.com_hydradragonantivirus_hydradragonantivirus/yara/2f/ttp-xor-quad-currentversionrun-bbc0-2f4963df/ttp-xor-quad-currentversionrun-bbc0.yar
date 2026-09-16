rule TTP_XOR_QUAD_CurrentVersionRun_bbc0 {
  strings:
    $key_bbc0 = { e8 af [2] cc a1 [2] e7 8d [2] c9 af [2] dd b4 [2] d2 ae [2] cc b3 [2] ce b2 [2] d5 b4 [2] c9 b3 [2] d5 9c }

  condition:
    any of them
}