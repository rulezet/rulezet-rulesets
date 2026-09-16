rule TTP_XOR_QUAD_CurrentVersionRun_d3dc {
  strings:
    $key_d3dc = { 80 b3 [2] a4 bd [2] 8f 91 [2] a1 b3 [2] b5 a8 [2] ba b2 [2] a4 af [2] a6 ae [2] bd a8 [2] a1 af [2] bd 80 }

  condition:
    any of them
}