rule TTP_XOR_QUAD_CurrentVersionRun_d3be {
  strings:
    $key_d3be = { 80 d1 [2] a4 df [2] 8f f3 [2] a1 d1 [2] b5 ca [2] ba d0 [2] a4 cd [2] a6 cc [2] bd ca [2] a1 cd [2] bd e2 }

  condition:
    any of them
}