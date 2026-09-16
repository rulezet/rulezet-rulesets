rule TTP_XOR_QUAD_CurrentVersionRun_d3d5 {
  strings:
    $key_d3d5 = { 80 ba [2] a4 b4 [2] 8f 98 [2] a1 ba [2] b5 a1 [2] ba bb [2] a4 a6 [2] a6 a7 [2] bd a1 [2] a1 a6 [2] bd 89 }

  condition:
    any of them
}