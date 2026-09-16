rule TTP_XOR_QUAD_CurrentVersionRun_c1ad {
  strings:
    $key_c1ad = { 92 c2 [2] b6 cc [2] 9d e0 [2] b3 c2 [2] a7 d9 [2] a8 c3 [2] b6 de [2] b4 df [2] af d9 [2] b3 de [2] af f1 }

  condition:
    any of them
}