rule TTP_XOR_QUAD_CurrentVersionRun_d6ab {
  strings:
    $key_d6ab = { 85 c4 [2] a1 ca [2] 8a e6 [2] a4 c4 [2] b0 df [2] bf c5 [2] a1 d8 [2] a3 d9 [2] b8 df [2] a4 d8 [2] b8 f7 }

  condition:
    any of them
}