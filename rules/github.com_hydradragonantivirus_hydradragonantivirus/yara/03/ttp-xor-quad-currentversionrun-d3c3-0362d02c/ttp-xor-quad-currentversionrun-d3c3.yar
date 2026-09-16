rule TTP_XOR_QUAD_CurrentVersionRun_d3c3 {
  strings:
    $key_d3c3 = { 80 ac [2] a4 a2 [2] 8f 8e [2] a1 ac [2] b5 b7 [2] ba ad [2] a4 b0 [2] a6 b1 [2] bd b7 [2] a1 b0 [2] bd 9f }

  condition:
    any of them
}