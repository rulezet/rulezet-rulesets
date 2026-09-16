rule TTP_XOR_QUAD_CurrentVersionRun_c9d3 {
  strings:
    $key_c9d3 = { 9a bc [2] be b2 [2] 95 9e [2] bb bc [2] af a7 [2] a0 bd [2] be a0 [2] bc a1 [2] a7 a7 [2] bb a0 [2] a7 8f }

  condition:
    any of them
}