rule TTP_XOR_QUAD_CurrentVersionRun_c3ad {
  strings:
    $key_c3ad = { 90 c2 [2] b4 cc [2] 9f e0 [2] b1 c2 [2] a5 d9 [2] aa c3 [2] b4 de [2] b6 df [2] ad d9 [2] b1 de [2] ad f1 }

  condition:
    any of them
}