rule TTP_XOR_QUAD_CurrentVersionRun_d3fc {
  strings:
    $key_d3fc = { 80 93 [2] a4 9d [2] 8f b1 [2] a1 93 [2] b5 88 [2] ba 92 [2] a4 8f [2] a6 8e [2] bd 88 [2] a1 8f [2] bd a0 }

  condition:
    any of them
}