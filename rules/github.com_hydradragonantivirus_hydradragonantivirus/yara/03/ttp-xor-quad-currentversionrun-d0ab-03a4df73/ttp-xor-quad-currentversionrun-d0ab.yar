rule TTP_XOR_QUAD_CurrentVersionRun_d0ab {
  strings:
    $key_d0ab = { 83 c4 [2] a7 ca [2] 8c e6 [2] a2 c4 [2] b6 df [2] b9 c5 [2] a7 d8 [2] a5 d9 [2] be df [2] a2 d8 [2] be f7 }

  condition:
    any of them
}