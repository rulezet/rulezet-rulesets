rule TTP_XOR_QUAD_CurrentVersionRun_c5ab {
  strings:
    $key_c5ab = { 96 c4 [2] b2 ca [2] 99 e6 [2] b7 c4 [2] a3 df [2] ac c5 [2] b2 d8 [2] b0 d9 [2] ab df [2] b7 d8 [2] ab f7 }

  condition:
    any of them
}