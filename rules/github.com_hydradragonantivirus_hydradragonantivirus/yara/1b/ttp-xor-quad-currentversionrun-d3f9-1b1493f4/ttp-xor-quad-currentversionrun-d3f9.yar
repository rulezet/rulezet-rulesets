rule TTP_XOR_QUAD_CurrentVersionRun_d3f9 {
  strings:
    $key_d3f9 = { 80 96 [2] a4 98 [2] 8f b4 [2] a1 96 [2] b5 8d [2] ba 97 [2] a4 8a [2] a6 8b [2] bd 8d [2] a1 8a [2] bd a5 }

  condition:
    any of them
}