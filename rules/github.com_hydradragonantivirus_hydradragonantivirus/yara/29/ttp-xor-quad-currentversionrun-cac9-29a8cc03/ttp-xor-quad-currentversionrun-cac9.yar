rule TTP_XOR_QUAD_CurrentVersionRun_cac9 {
  strings:
    $key_cac9 = { 99 a6 [2] bd a8 [2] 96 84 [2] b8 a6 [2] ac bd [2] a3 a7 [2] bd ba [2] bf bb [2] a4 bd [2] b8 ba [2] a4 95 }

  condition:
    any of them
}