rule TTP_XOR_QUAD_CurrentVersionRun_c4ab {
  strings:
    $key_c4ab = { 97 c4 [2] b3 ca [2] 98 e6 [2] b6 c4 [2] a2 df [2] ad c5 [2] b3 d8 [2] b1 d9 [2] aa df [2] b6 d8 [2] aa f7 }

  condition:
    any of them
}