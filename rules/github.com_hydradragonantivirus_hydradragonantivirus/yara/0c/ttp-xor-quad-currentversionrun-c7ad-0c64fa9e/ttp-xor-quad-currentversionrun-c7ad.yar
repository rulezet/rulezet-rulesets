rule TTP_XOR_QUAD_CurrentVersionRun_c7ad {
  strings:
    $key_c7ad = { 94 c2 [2] b0 cc [2] 9b e0 [2] b5 c2 [2] a1 d9 [2] ae c3 [2] b0 de [2] b2 df [2] a9 d9 [2] b5 de [2] a9 f1 }

  condition:
    any of them
}