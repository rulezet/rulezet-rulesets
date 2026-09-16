rule TTP_XOR_QUAD_CurrentVersionRun_68ab {
  strings:
    $key_68ab = { 3b c4 [2] 1f ca [2] 34 e6 [2] 1a c4 [2] 0e df [2] 01 c5 [2] 1f d8 [2] 1d d9 [2] 06 df [2] 1a d8 [2] 06 f7 }

  condition:
    any of them
}