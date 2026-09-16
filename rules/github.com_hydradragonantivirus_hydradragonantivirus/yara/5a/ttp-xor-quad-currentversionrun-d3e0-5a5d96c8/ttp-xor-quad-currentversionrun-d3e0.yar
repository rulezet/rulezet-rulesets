rule TTP_XOR_QUAD_CurrentVersionRun_d3e0 {
  strings:
    $key_d3e0 = { 80 8f [2] a4 81 [2] 8f ad [2] a1 8f [2] b5 94 [2] ba 8e [2] a4 93 [2] a6 92 [2] bd 94 [2] a1 93 [2] bd bc }

  condition:
    any of them
}