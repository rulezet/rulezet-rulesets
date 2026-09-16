rule TTP_XOR_QUAD_CurrentVersionRun_d5ce {
  strings:
    $key_d5ce = { 86 a1 [2] a2 af [2] 89 83 [2] a7 a1 [2] b3 ba [2] bc a0 [2] a2 bd [2] a0 bc [2] bb ba [2] a7 bd [2] bb 92 }

  condition:
    any of them
}