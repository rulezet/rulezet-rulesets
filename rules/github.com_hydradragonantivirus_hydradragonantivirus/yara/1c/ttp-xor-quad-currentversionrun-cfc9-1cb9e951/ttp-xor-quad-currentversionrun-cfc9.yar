rule TTP_XOR_QUAD_CurrentVersionRun_cfc9 {
  strings:
    $key_cfc9 = { 9c a6 [2] b8 a8 [2] 93 84 [2] bd a6 [2] a9 bd [2] a6 a7 [2] b8 ba [2] ba bb [2] a1 bd [2] bd ba [2] a1 95 }

  condition:
    any of them
}