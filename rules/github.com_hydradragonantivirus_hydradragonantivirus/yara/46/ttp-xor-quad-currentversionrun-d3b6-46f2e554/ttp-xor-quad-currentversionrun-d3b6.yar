rule TTP_XOR_QUAD_CurrentVersionRun_d3b6 {
  strings:
    $key_d3b6 = { 80 d9 [2] a4 d7 [2] 8f fb [2] a1 d9 [2] b5 c2 [2] ba d8 [2] a4 c5 [2] a6 c4 [2] bd c2 [2] a1 c5 [2] bd ea }

  condition:
    any of them
}