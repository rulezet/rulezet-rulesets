rule TTP_XOR_QUAD_CurrentVersionRun_d3f1 {
  strings:
    $key_d3f1 = { 80 9e [2] a4 90 [2] 8f bc [2] a1 9e [2] b5 85 [2] ba 9f [2] a4 82 [2] a6 83 [2] bd 85 [2] a1 82 [2] bd ad }

  condition:
    any of them
}