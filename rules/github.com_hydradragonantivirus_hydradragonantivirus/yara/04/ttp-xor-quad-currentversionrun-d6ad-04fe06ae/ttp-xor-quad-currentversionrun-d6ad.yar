rule TTP_XOR_QUAD_CurrentVersionRun_d6ad {
  strings:
    $key_d6ad = { 85 c2 [2] a1 cc [2] 8a e0 [2] a4 c2 [2] b0 d9 [2] bf c3 [2] a1 de [2] a3 df [2] b8 d9 [2] a4 de [2] b8 f1 }

  condition:
    any of them
}