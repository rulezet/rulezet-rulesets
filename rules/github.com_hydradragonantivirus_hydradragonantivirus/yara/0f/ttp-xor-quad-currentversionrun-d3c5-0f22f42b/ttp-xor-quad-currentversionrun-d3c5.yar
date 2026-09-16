rule TTP_XOR_QUAD_CurrentVersionRun_d3c5 {
  strings:
    $key_d3c5 = { 80 aa [2] a4 a4 [2] 8f 88 [2] a1 aa [2] b5 b1 [2] ba ab [2] a4 b6 [2] a6 b7 [2] bd b1 [2] a1 b6 [2] bd 99 }

  condition:
    any of them
}