rule TTP_XOR_QUAD_CurrentVersionRun_cac7 {
  strings:
    $key_cac7 = { 99 a8 [2] bd a6 [2] 96 8a [2] b8 a8 [2] ac b3 [2] a3 a9 [2] bd b4 [2] bf b5 [2] a4 b3 [2] b8 b4 [2] a4 9b }

  condition:
    any of them
}