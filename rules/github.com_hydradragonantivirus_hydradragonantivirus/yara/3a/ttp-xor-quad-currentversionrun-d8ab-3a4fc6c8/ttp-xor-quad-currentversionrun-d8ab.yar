rule TTP_XOR_QUAD_CurrentVersionRun_d8ab {
  strings:
    $key_d8ab = { 8b c4 [2] af ca [2] 84 e6 [2] aa c4 [2] be df [2] b1 c5 [2] af d8 [2] ad d9 [2] b6 df [2] aa d8 [2] b6 f7 }

  condition:
    any of them
}