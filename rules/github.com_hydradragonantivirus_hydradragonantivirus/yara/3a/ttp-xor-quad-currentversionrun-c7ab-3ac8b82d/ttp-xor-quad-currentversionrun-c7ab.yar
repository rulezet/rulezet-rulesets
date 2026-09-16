rule TTP_XOR_QUAD_CurrentVersionRun_c7ab {
  strings:
    $key_c7ab = { 94 c4 [2] b0 ca [2] 9b e6 [2] b5 c4 [2] a1 df [2] ae c5 [2] b0 d8 [2] b2 d9 [2] a9 df [2] b5 d8 [2] a9 f7 }

  condition:
    any of them
}