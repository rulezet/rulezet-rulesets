rule TTP_XOR_QUAD_CurrentVersionRun_d3d9 {
  strings:
    $key_d3d9 = { 80 b6 [2] a4 b8 [2] 8f 94 [2] a1 b6 [2] b5 ad [2] ba b7 [2] a4 aa [2] a6 ab [2] bd ad [2] a1 aa [2] bd 85 }

  condition:
    any of them
}