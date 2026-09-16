rule TTP_XOR_QUAD_CurrentVersionRun_c2ad {
  strings:
    $key_c2ad = { 91 c2 [2] b5 cc [2] 9e e0 [2] b0 c2 [2] a4 d9 [2] ab c3 [2] b5 de [2] b7 df [2] ac d9 [2] b0 de [2] ac f1 }

  condition:
    any of them
}