rule TTP_XOR_QUAD_CurrentVersionRun_d3ce {
  strings:
    $key_d3ce = { 80 a1 [2] a4 af [2] 8f 83 [2] a1 a1 [2] b5 ba [2] ba a0 [2] a4 bd [2] a6 bc [2] bd ba [2] a1 bd [2] bd 92 }

  condition:
    any of them
}