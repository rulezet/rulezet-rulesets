rule TTP_XOR_QUAD_CurrentVersionRun_d6b1 {
  strings:
    $key_d6b1 = { 85 de [2] a1 d0 [2] 8a fc [2] a4 de [2] b0 c5 [2] bf df [2] a1 c2 [2] a3 c3 [2] b8 c5 [2] a4 c2 [2] b8 ed }

  condition:
    any of them
}