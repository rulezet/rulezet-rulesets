rule TTP_XOR_QUAD_CurrentVersionRun_d7ab {
  strings:
    $key_d7ab = { 84 c4 [2] a0 ca [2] 8b e6 [2] a5 c4 [2] b1 df [2] be c5 [2] a0 d8 [2] a2 d9 [2] b9 df [2] a5 d8 [2] b9 f7 }

  condition:
    any of them
}