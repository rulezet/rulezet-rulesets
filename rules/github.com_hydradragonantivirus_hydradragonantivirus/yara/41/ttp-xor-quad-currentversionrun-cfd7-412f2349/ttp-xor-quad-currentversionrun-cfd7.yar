rule TTP_XOR_QUAD_CurrentVersionRun_cfd7 {
  strings:
    $key_cfd7 = { 9c b8 [2] b8 b6 [2] 93 9a [2] bd b8 [2] a9 a3 [2] a6 b9 [2] b8 a4 [2] ba a5 [2] a1 a3 [2] bd a4 [2] a1 8b }

  condition:
    any of them
}