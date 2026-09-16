rule TTP_XOR_QUAD_CurrentVersionRun_d3df {
  strings:
    $key_d3df = { 80 b0 [2] a4 be [2] 8f 92 [2] a1 b0 [2] b5 ab [2] ba b1 [2] a4 ac [2] a6 ad [2] bd ab [2] a1 ac [2] bd 83 }

  condition:
    any of them
}