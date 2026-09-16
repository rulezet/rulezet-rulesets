rule TTP_XOR_QUAD_CurrentVersionRun_c0ad {
  strings:
    $key_c0ad = { 93 c2 [2] b7 cc [2] 9c e0 [2] b2 c2 [2] a6 d9 [2] a9 c3 [2] b7 de [2] b5 df [2] ae d9 [2] b2 de [2] ae f1 }

  condition:
    any of them
}