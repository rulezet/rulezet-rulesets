rule TTP_XOR_QUAD_CurrentVersionRun_d3ff {
  strings:
    $key_d3ff = { 80 90 [2] a4 9e [2] 8f b2 [2] a1 90 [2] b5 8b [2] ba 91 [2] a4 8c [2] a6 8d [2] bd 8b [2] a1 8c [2] bd a3 }

  condition:
    any of them
}