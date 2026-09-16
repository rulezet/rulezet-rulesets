rule TTP_XOR_QUAD_CurrentVersionRun_cfc6 {
  strings:
    $key_cfc6 = { 9c a9 [2] b8 a7 [2] 93 8b [2] bd a9 [2] a9 b2 [2] a6 a8 [2] b8 b5 [2] ba b4 [2] a1 b2 [2] bd b5 [2] a1 9a }

  condition:
    any of them
}