rule TTP_XOR_QUAD_CurrentVersionRun_08ab {
  strings:
    $key_08ab = { 5b c4 [2] 7f ca [2] 54 e6 [2] 7a c4 [2] 6e df [2] 61 c5 [2] 7f d8 [2] 7d d9 [2] 66 df [2] 7a d8 [2] 66 f7 }

  condition:
    any of them
}