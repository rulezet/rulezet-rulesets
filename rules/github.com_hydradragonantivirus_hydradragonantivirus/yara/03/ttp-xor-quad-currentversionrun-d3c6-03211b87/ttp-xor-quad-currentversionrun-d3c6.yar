rule TTP_XOR_QUAD_CurrentVersionRun_d3c6 {
  strings:
    $key_d3c6 = { 80 a9 [2] a4 a7 [2] 8f 8b [2] a1 a9 [2] b5 b2 [2] ba a8 [2] a4 b5 [2] a6 b4 [2] bd b2 [2] a1 b5 [2] bd 9a }

  condition:
    any of them
}