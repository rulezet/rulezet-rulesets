rule TTP_XOR_QUAD_CurrentVersionRun_d3f4 {
  strings:
    $key_d3f4 = { 80 9b [2] a4 95 [2] 8f b9 [2] a1 9b [2] b5 80 [2] ba 9a [2] a4 87 [2] a6 86 [2] bd 80 [2] a1 87 [2] bd a8 }

  condition:
    any of them
}