rule TTP_XOR_QUAD_CurrentVersionRun_d0e1 {
  strings:
    $key_d0e1 = { 83 8e [2] a7 80 [2] 8c ac [2] a2 8e [2] b6 95 [2] b9 8f [2] a7 92 [2] a5 93 [2] be 95 [2] a2 92 [2] be bd }

  condition:
    any of them
}