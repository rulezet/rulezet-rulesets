rule TTP_XOR_QUAD_CurrentVersionRun_c6ab {
  strings:
    $key_c6ab = { 95 c4 [2] b1 ca [2] 9a e6 [2] b4 c4 [2] a0 df [2] af c5 [2] b1 d8 [2] b3 d9 [2] a8 df [2] b4 d8 [2] a8 f7 }

  condition:
    any of them
}