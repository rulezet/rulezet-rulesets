rule TTP_XOR_QUAD_CurrentVersionRun_eaab {
  strings:
    $key_eaab = { b9 c4 [2] 9d ca [2] b6 e6 [2] 98 c4 [2] 8c df [2] 83 c5 [2] 9d d8 [2] 9f d9 [2] 84 df [2] 98 d8 [2] 84 f7 }

  condition:
    any of them
}