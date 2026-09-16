rule TTP_XOR_QUAD_CurrentVersionRun_cad7 {
  strings:
    $key_cad7 = { 99 b8 [2] bd b6 [2] 96 9a [2] b8 b8 [2] ac a3 [2] a3 b9 [2] bd a4 [2] bf a5 [2] a4 a3 [2] b8 a4 [2] a4 8b }

  condition:
    any of them
}