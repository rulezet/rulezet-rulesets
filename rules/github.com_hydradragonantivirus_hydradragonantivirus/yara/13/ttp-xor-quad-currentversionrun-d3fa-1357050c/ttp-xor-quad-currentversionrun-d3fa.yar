rule TTP_XOR_QUAD_CurrentVersionRun_d3fa {
  strings:
    $key_d3fa = { 80 95 [2] a4 9b [2] 8f b7 [2] a1 95 [2] b5 8e [2] ba 94 [2] a4 89 [2] a6 88 [2] bd 8e [2] a1 89 [2] bd a6 }

  condition:
    any of them
}