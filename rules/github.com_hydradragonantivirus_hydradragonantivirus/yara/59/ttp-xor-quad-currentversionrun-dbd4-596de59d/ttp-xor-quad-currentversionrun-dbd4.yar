rule TTP_XOR_QUAD_CurrentVersionRun_dbd4 {
  strings:
    $key_dbd4 = { 88 bb [2] ac b5 [2] 87 99 [2] a9 bb [2] bd a0 [2] b2 ba [2] ac a7 [2] ae a6 [2] b5 a0 [2] a9 a7 [2] b5 88 }

  condition:
    any of them
}