rule TTP_XOR_QUAD_CurrentVersionRun_d6ce {
  strings:
    $key_d6ce = { 85 a1 [2] a1 af [2] 8a 83 [2] a4 a1 [2] b0 ba [2] bf a0 [2] a1 bd [2] a3 bc [2] b8 ba [2] a4 bd [2] b8 92 }

  condition:
    any of them
}