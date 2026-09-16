rule TTP_XOR_QUAD_CurrentVersionRun_d3e1 {
  strings:
    $key_d3e1 = { 80 8e [2] a4 80 [2] 8f ac [2] a1 8e [2] b5 95 [2] ba 8f [2] a4 92 [2] a6 93 [2] bd 95 [2] a1 92 [2] bd bd }

  condition:
    any of them
}