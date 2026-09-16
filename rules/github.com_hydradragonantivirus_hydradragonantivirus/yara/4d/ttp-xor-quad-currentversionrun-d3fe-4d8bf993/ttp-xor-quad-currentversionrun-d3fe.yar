rule TTP_XOR_QUAD_CurrentVersionRun_d3fe {
  strings:
    $key_d3fe = { 80 91 [2] a4 9f [2] 8f b3 [2] a1 91 [2] b5 8a [2] ba 90 [2] a4 8d [2] a6 8c [2] bd 8a [2] a1 8d [2] bd a2 }

  condition:
    any of them
}